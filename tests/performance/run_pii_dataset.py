#!/usr/bin/env python3
"""Offline PII evaluation: real native engine and guarded Gateway, local upstream only."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import platform
import random
import select
import socket
import subprocess
import sys
import threading
import time

from pii_dataset import load_jsonl, score
from http_workload import quantiles
from resources import Sampler, window
from run_streams import clock_quality

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'examples/edge'))
import local_assistant as edge


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


class Upstream(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def setup(self):
        super().setup()
        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def log_message(self, *_):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        identity = self.headers.get('x-dataset-id')
        with self.server.lock:
            self.server.calls += 1
            valid = (identity in self.server.expected and self.path == '/v1/chat/completions'
                     and self.headers.get('Authorization') is None
                     and body['messages'][0]['content'] == self.server.expected.get(identity))
            if not valid:
                self.server.mismatches.append(identity)
        wire = json.dumps({'id': 'fixture', 'object': 'chat.completion', 'created': 1,
            'model': 'dataset-fixture', 'choices': [{'index': 0, 'finish_reason': 'stop',
            'message': {'role': 'assistant', 'content': 'READY'}}]}).encode()
        self.send_response(200 if valid else 502)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(wire)))
        self.end_headers()
        self.wfile.write(wire)


def request(connection, path, body, headers, expected):
    begin = time.monotonic_ns()
    connection.request('POST', path, json.dumps(body), {'Content-Type': 'application/json', **headers})
    response = connection.getresponse()
    raw = response.read(1048577)
    if response.status != expected or len(raw) > 1048576:
        raise RuntimeError('unexpected HTTP response: ' + str(response.status))
    result = json.loads(raw)
    if expected == 200 and result['choices'][0]['message']['content'] != 'READY':
        raise RuntimeError('invalid fixture completion')
    return result, (time.monotonic_ns() - begin) / 1e6


def gateway_case(binary, directory, records, outcomes, mode, concurrency=1):
    directory.mkdir()
    expected = {row['id']: outcomes[row['id']]['text'] if mode == 'mask' else row['text'] for row in records}
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
    server.daemon_threads = True
    server.expected, server.calls, server.mismatches, server.lock = expected, 0, [], threading.Lock()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    process = None
    sampler = Sampler(directory / 'resources.jsonl')
    timings = []
    failures = []
    log = (directory / 'gateway.log').open('w')
    try:
        reserved = [socket.socket() for _ in range(3)]
        try:
            for sock in reserved:
                sock.bind(('127.0.0.1', 0))
            port, mcp_port, tool_port = [sock.getsockname()[1] for sock in reserved]
            state = directory / 'state'
            config = edge.provision(state, 'dataset-fixture', f'http://127.0.0.1:{server.server_port}/v1',
                                    port, mcp_port, tool_port)
        finally:
            for sock in reserved:
                sock.close()
        system = config['aiSystems'][0]
        del system['mcp']
        security = system['security']
        del security['mcpSessions']
        security['policies'] = [p for p in security['policies'] if p['id'] in ('model', 'execution/create', 'execution/cancel')]
        security['requiredAudit']['actionTypes'] = ['modelInvoke', 'executionOperation']
        security['executionBudget'].update(maxDurationSeconds=600, maxModelCalls=len(records) + 20,
            maxToolCalls=0, maxAgentCalls=0, maxAttempts=2 * len(records) + 40, maxConcurrent=concurrency)
        if mode == 'disabled':
            security['pii']['enabled'] = False
        elif mode == 'block':
            security['pii']['policy'] = {'entities': {k: {'action': 'block'} for k in
                ('EMAIL_ADDRESS', 'PHONE_NUMBER', 'IP_ADDRESS')}}
        path = state / 'gateway.json'
        path.write_text(json.dumps(config))
        read_fd, write_fd = os.pipe()
        try:
            process = subprocess.Popen([str(binary), '--file', str(path)], stdout=log, stderr=subprocess.STDOUT,
                env=dict(os.environ, READY_FD=str(write_fd), RUST_LOG='warn', PPROF_ALLOC_ALLOCATOR='system'),
                pass_fds=(write_fd,))
        finally:
            os.close(write_fd)
        try:
            if not select.select([read_fd], [], [], 30)[0] or os.read(read_fd, 1) != b'' or process.poll() is not None:
                raise RuntimeError('Gateway readiness failed')
        finally:
            os.close(read_fd)
        token = (state / 'caller.jwt').read_text()
        headers = {'Authorization': 'Bearer ' + token}
        control = http.client.HTTPConnection('127.0.0.1', port, timeout=15)
        try:
            value, _ = request(control, '/v1/executions', {}, headers, 201)
            execution = value['executionId']
        finally:
            control.close()
        headers['x-aisp-execution-id'] = execution
        sampler.attach('gateway', process)
        sampler.start()
        time.sleep(.3)
        begin = time.monotonic_ns()
        def lane(items):
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=15)
            try:
                for row in items:
                    try:
                        _, elapsed = request(connection, '/v1/chat/completions', {
                            'model': 'dataset-fixture', 'messages': [{'role': 'user', 'content': row['text']}],
                            'max_completion_tokens': 8}, {**headers, 'x-dataset-id': row['id']},
                            403 if mode == 'block' else 200)
                        timings.append({'id': row['id'], 'elapsedMs': elapsed})
                    except Exception as error:
                        failures.append({'id': row['id'], 'errorType': type(error).__name__})
                        raise
            finally:
                connection.close()
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            list(pool.map(lane, [records[i::concurrency] for i in range(concurrency)]))
        end = time.monotonic_ns()
        time.sleep(.3)
        resources = window(sampler.rows, 'gateway', begin, end)
        quality = clock_quality(sampler.rows)
        if not resources or not quality['valid'] or server.mismatches:
            raise RuntimeError('measurement or outbound payload validation failed')
        expected_calls = 0 if mode == 'block' else len(records)
        if server.calls != expected_calls:
            raise RuntimeError('unexpected upstream call count')
        result = {'successful': True, 'mode': mode, 'concurrency': concurrency,
            'requests': len(timings), 'actualUpstreamCalls': server.calls, 'payloadMismatches': len(server.mismatches),
            'latencyMs': quantiles([v['elapsedMs'] for v in timings]),
            'elapsedSeconds': (end - begin) / 1e9, 'resources': resources, 'clockQuality': quality}
        save(directory / 'summary.json', result)
        return result
    finally:
        sampler.stop()
        save(directory / 'requests.json', {'completed': timings, 'failures': failures,
            'upstreamCalls': server.calls, 'payloadMismatches': server.mismatches})
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(5)
        log.close()
        server.shutdown()
        server.server_close()
        thread.join(5)
        if sampler.errors:
            raise RuntimeError('resource sampling failed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', required=True, type=Path)
    parser.add_argument('--engine-binary', required=True, type=Path)
    parser.add_argument('--gateway-binary', required=True, type=Path)
    parser.add_argument('--sample-size', default=1000, type=int)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=False)
    records = load_jsonl(args.data)
    manifest = json.loads(args.data.with_name('manifest.json').read_text())
    if hashlib.sha256(args.data.read_bytes()).hexdigest() != manifest['normalizedSha256']:
        raise ValueError('normalized input differs from manifest')
    save(args.out / 'input-manifest.json', manifest)
    with args.data.open() as source, (args.out / 'engine.jsonl').open('w') as output:
        subprocess.run([str(args.engine_binary.resolve())], stdin=source, stdout=output, check=True, timeout=120)
    outcomes = load_jsonl(args.out / 'engine.jsonl')
    quality = score(records, outcomes, manifest.get('annotationMethod', 'literal-occurrence'))
    save(args.out / 'quality.json', quality)
    if quality['engineErrors']:
        raise RuntimeError('PII engine errors; inspect quality report')
    references = {row['id']: row for row in outcomes}
    sample = random.Random(20261104).sample(records, min(args.sample_size, len(records)))
    save(args.out / 'sample-ids.json', [r['id'] for r in sample])
    summary = {'successful': False, 'environment': platform.platform(), 'seed': 20261104,
        'engineInspectLatencyMs': quantiles([v['elapsedNs'] / 1e6 for v in outcomes]), 'cases': [],
        'limitations': 'two C1 rounds in AB/BA order; local deterministic upstream, full JWT/Agent/authorization/budget/audit active; only PII differs; no cloud or model weights; engine timings exclude construction and JSON I/O; synthetic English; source annotation method and exclusions in input manifest; no dedicated negative set'}
    try:
        for index, modes in enumerate((('disabled', 'mask'), ('mask', 'disabled')), 1):
            for mode in modes:
                result = gateway_case(args.gateway_binary.resolve(), args.out / f'{mode}-r{index}', sample, references, mode)
                summary['cases'].append(result)
                save(args.out / 'summary.json', summary)
        concurrent = sample[:100]
        summary['cases'].append(gateway_case(args.gateway_binary.resolve(), args.out / 'mask-c4', concurrent, references, 'mask', 4))
        block = [row for row in sample if references[row['id']]['findings']][:100]
        if not block:
            raise RuntimeError('no blockable test cases')
        summary['cases'].append(gateway_case(args.gateway_binary.resolve(), args.out / 'block', block, references, 'block'))
        summary['successful'] = True
    except Exception as error:
        summary['errorType'] = type(error).__name__
    save(args.out / 'summary.json', summary)
    print(json.dumps({'successful': summary['successful'], 'engineDocuments': len(records),
        'gatewayCases': len(summary['cases']), 'errorType': summary.get('errorType')}))
    return 0 if summary['successful'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
