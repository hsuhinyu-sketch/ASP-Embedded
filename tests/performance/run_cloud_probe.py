#!/usr/bin/env python3
"""Finite cloud JSON/SSE and local security probe. Reports contain no API keys or JWTs.

Uses the existing edge identity helper, Gateway APIs and process sampler. This is a small
connectivity/performance experiment, not a capacity benchmark or model-safety evaluation.
"""
import argparse
import base64
import concurrent.futures
import copy
from dataclasses import dataclass
import http.client
import json
import os
from pathlib import Path
import select
import socket
import ssl
import subprocess
import sys
import threading
import time
import traceback

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'examples/edge'))
import local_assistant as edge
from resources import Sampler, window
from run_streams import clock_quality

@dataclass(frozen=True)
class CloudTarget:
    host: str
    model: str
    api_key_header: str = 'Authorization'

    def headers(self, key):
        return {self.api_key_header: 'Bearer ' + key if self.api_key_header == 'Authorization' else key}

    def payload(self):
        value = {'model': self.model, 'messages': [{'role': 'user', 'content': 'Reply exactly READY.'}],
                 'temperature': 0, 'stream': False}
        if self.api_key_header == 'api-key':
            value.update(max_completion_tokens=32, thinking={'type': 'disabled'})
            value['messages'] = [{'role': 'user', 'content':
                'Output only the five uppercase letters READY, without punctuation or explanation.'}]
        else:
            value['max_tokens'] = 32
        return value

    def backend(self, key_file):
        value = {'params': {'baseUrl': 'https://' + self.host + '/v1'}}
        if self.api_key_header == 'Authorization':
            value['params']['apiKey'] = {'file': str(key_file)}
        else:
            value['auth'] = {'key': {'value': {'file': str(key_file)},
                                     'location': {'header': {'name': self.api_key_header}}}}
        return value


TARGETS = {'pai': CloudTarget('cn-beijing.pai-token.aliyuncs.com', 'qwen3.8-max'),
           'mimo': CloudTarget('api.xiaomimimo.com', 'mimo-v2.6-pro', 'api-key')}
PAI = TARGETS['pai']
LIMIT = 1024 * 1024


class CompletionError(ValueError):
    """Safe diagnostics: never include provider bodies or credentials in summaries."""
    def __init__(self, **state):
        super().__init__('completion failed probe validation')
        self.state = state


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def completion(response, stream, started):
    if not stream:
        raw = response.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise ValueError('JSON response exceeds probe limit')
        value = json.loads(raw)
        if 'error' in value:
            raise ValueError('upstream returned an error object')
        choice = value['choices'][0]
        content = choice['message'].get('content') or ''
        if choice['finish_reason'] != 'stop' or content.strip() != 'READY':
            raise CompletionError(finishedNormally=choice['finish_reason'] == 'stop',
                                  answerMatched=content.strip() == 'READY', contentCharacters=len(content))
        return {'usage': value.get('usage'), 'bodyBytes': len(raw), 'firstContentMs': None}
    if 'text/event-stream' not in response.getheader('Content-Type', ''):
        raise ValueError('expected SSE Content-Type')
    total, first, usage, done, finished = 0, None, None, False, False
    text, data = [], []
    while True:
        line = response.readline(65537)
        if not line:
            break
        total += len(line)
        if len(line) > 65536 or total > LIMIT:
            raise ValueError('SSE response exceeds probe limit')
        line = line.rstrip(b'\r\n')
        if line.startswith(b'data:'):
            data.append(line[5:].lstrip(b' '))
        elif not line and data:
            frame = b'\n'.join(data)
            data.clear()
            if frame == b'[DONE]':
                done = True
                continue
            if done:
                raise ValueError('SSE data arrived after DONE')
            value = json.loads(frame)
            if 'error' in value:
                raise ValueError('SSE returned an error event')
            if value.get('usage'):
                usage = value['usage']
            for choice in value.get('choices', []):
                part = choice.get('delta', {}).get('content')
                if part:
                    if finished:
                        raise ValueError('SSE content arrived after finish_reason')
                    first = first if first is not None else (time.monotonic() - started) * 1000
                    text.append(part)
                if choice.get('finish_reason') is not None:
                    if choice['finish_reason'] != 'stop' or finished:
                        raise ValueError('unexpected SSE finish_reason')
                    finished = True
    if data or not done or not finished or ''.join(text).strip() != 'READY':
        raise CompletionError(pendingEvent=bool(data), donePresent=done, finishPresent=finished,
                              answerMatched=''.join(text).strip() == 'READY',
                              contentCharacters=sum(map(len, text)))
    return {'usage': usage, 'bodyBytes': total, 'firstContentMs': first}


class Gateway:
    def __init__(self, binary, directory, key_file, observer=None, target=PAI):
        self.directory = directory
        self.target = target
        sockets = [socket.socket(), socket.socket()]
        try:
            for sock in sockets:
                sock.bind(('127.0.0.1', 0))
            self.port, unused = [sock.getsockname()[1] for sock in sockets]
            state = directory / 'state'
            self.config = edge.provision(state, target.model, 'http://127.0.0.1:11434/v1', self.port, unused)
        finally:
            for sock in sockets:
                sock.close()
        system = self.config['aiSystems'][0]
        del system['mcp']
        security = system['security']
        del security['mcpSessions']
        security['policies'] = [p for p in security['policies'] if p['id'] in ('model', 'execution/create', 'execution/cancel')]
        security['dataEgress'] = {'classification': 'internal', 'modelDestinations': [target.host + ':443']}
        # Cancelled records remain until TTL. Warm-up plus three rounds create ten contexts.
        security['executionBudget'].update(maxToolCalls=0, maxAgentCalls=0, maxContextsPerOwner=16)
        system['llm']['models'][0].update(target.backend(key_file))
        self.path = state / 'gateway.json'
        self.path.write_text(json.dumps(self.config))
        self.token = (state / 'caller.jwt').read_text()
        self.seed = (state / 'issuer.key').read_bytes()
        self.trace = directory / 'socket-trace.jsonl'
        self.log_path = directory / 'gateway.log'
        self.log = self.log_path.open('w')
        env = dict(os.environ, RUST_LOG='info,ai_security_platform_runtime::state_manager=debug',
                   PPROF_ALLOC_ALLOCATOR='system')
        if observer:
            env.update(LD_PRELOAD=str(observer), AISP_SOCKET_TRACE=str(self.trace))
        ready_read, ready_write = os.pipe()
        env['READY_FD'] = str(ready_write)
        try:
            self.process = subprocess.Popen([str(binary), '--file', str(self.path)], env=env,
                pass_fds=(ready_write,), stdout=self.log, stderr=subprocess.STDOUT)
        finally:
            os.close(ready_write)
        try:
            if not select.select([ready_read], [], [], 30)[0] or os.read(ready_read, 1) != b'':
                raise RuntimeError('Gateway READY_FD timeout')
            if self.process.poll() is not None:
                raise RuntimeError('Gateway exited before readiness; inspect private log')
            with socket.create_connection(('127.0.0.1', self.port), timeout=2):
                pass
        except BaseException:
            self.close()
            raise
        finally:
            os.close(ready_read)

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(5)
        self.log.close()

    def connection(self):
        return http.client.HTTPConnection('127.0.0.1', self.port, timeout=30)

    def control(self, path, execution=None, token=None):
        headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + (self.token if token is None else token)}
        if execution:
            headers['x-aisp-execution-id'] = execution
        c = self.connection()
        try:
            c.request('POST', path, '{}', headers)
            response = c.getresponse()
            raw = response.read(65537)
            if response.status not in (200, 201):
                return response.status, None
            return response.status, json.loads(raw)
        finally:
            c.close()

    def execution(self):
        status, value = self.control('/v1/executions')
        if status != 201:
            raise RuntimeError('execution creation denied')
        return value['executionId']

    def signed(self, **overrides):
        head, body, _ = self.token.split('.')
        claims = json.loads(base64.urlsafe_b64decode(body + '=' * (-len(body) % 4)))
        claims.update(overrides)
        message = (head + '.' + edge.b64(json.dumps(claims).encode())).encode()
        return message.decode() + '.' + edge.b64(edge.ed25519(self.seed, message))

    def reload(self, change):
        value = copy.deepcopy(self.config)
        change(value['aiSystems'][0]['security'])
        offset = self.log_path.stat().st_size
        candidate = self.path.with_suffix('.next')
        candidate.write_text(json.dumps(value))
        candidate.replace(self.path)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if 'Config reloaded successfully' in self.log_path.read_text()[offset:]:
                return
            if self.process.poll() is not None:
                raise RuntimeError('Gateway exited during reload')
            time.sleep(.05)
        raise RuntimeError('configuration update was not published')

    def cloud_writes(self):
        events = [json.loads(line) for line in self.trace.read_text().splitlines()]
        return sum(e['pid'] == self.process.pid and e['peer'].endswith(':443') and e['ret'] > 0
                   and e['op'] in ('write', 'writev', 'send', 'sendto', 'sendmsg') for e in events)


def call(connection, headers, stream=False, payload=None, expected=200, target=PAI):
    value = {**target.payload(), 'stream': stream, **(payload or {})}
    if stream:
        value['stream_options'] = {'include_usage': True}
    started = time.monotonic()
    connection.request('POST', '/v1/chat/completions', json.dumps(value),
                       {'Content-Type': 'application/json', **headers})
    response = connection.getresponse()
    if expected != 200:
        response.read(LIMIT + 1)
        if response.status != expected:
            raise ValueError('expected an authorization/budget refusal, got HTTP ' + str(response.status))
        return {'status': response.status}
    if response.status != 200:
        response.read(LIMIT + 1)
        raise ValueError('model HTTP status ' + str(response.status))
    parsed = completion(response, stream, started)
    return {'status': 200, 'elapsedMs': (time.monotonic() - started) * 1000, **parsed}


def gateway_call(gateway, execution, **options):
    headers = {'Authorization': 'Bearer ' + options.pop('token', gateway.token)}
    if execution:
        headers['x-aisp-execution-id'] = execution
    c = gateway.connection()
    try:
        return call(c, headers, target=gateway.target, **options)
    finally:
        c.close()


def security_probe(binary, output, key_file, observer, target=PAI):
    gateway = Gateway(binary, output, key_file, observer, target)
    results = []
    def denied(name, execution, **options):
        before = gateway.cloud_writes()
        result = gateway_call(gateway, execution, expected=options.pop('expected', 403), **options)
        time.sleep(.05)
        delta = gateway.cloud_writes() - before
        if delta:
            raise AssertionError(name + ': denied request produced cloud socket writes')
        results.append({'case': name, **result, 'cloudSocketWrites': delta})
        save(output / 'cases.json', results)
    try:
        execution = gateway.execution()
        for stream in (False, True):
            result = gateway_call(gateway, execution, stream=stream)
            results.append({'case': 'normal-sse' if stream else 'normal-json', **result})
            save(output / 'cases.json', results)
        if gateway.cloud_writes() == 0:
            raise AssertionError('socket observer did not observe successful cloud calls')
        denied('missing-jwt', execution, token='', expected=401)
        head, body, signature = gateway.token.split('.')
        bad = head + '.' + body + '.' + ('A' if signature[0] != 'A' else 'B') + signature[1:]
        denied('bad-signature', execution, token=bad, expected=401)
        denied('expired-jwt', execution, token=gateway.signed(exp=int(time.time()) - 120), expected=401)
        denied('foreign-tenant', execution, token=gateway.signed(tenant_id='foreign'))
        denied('missing-execution', None)
        denied('unknown-model', execution, payload={'model': 'not-authorized'}, expected=404)
        denied('model-call-budget-exhausted', execution, expected=429)
        gateway.control('/v1/executions/cancel', execution)
        denied('cancelled-execution', execution, expected=409)
        execution = gateway.execution()
        def block_email(s):
            s['pii']['policy'] = {'entities': {'EMAIL_ADDRESS': {'action': 'block'}}}
        gateway.reload(block_email)
        denied('configuration-invalidated-execution', execution)
        execution = gateway.execution()
        denied('pii-block', execution, payload={'messages': [{'role': 'user', 'content': 'Contact alice@example.com.'}]})
        gateway.reload(lambda s: s['policies'].append({'id': 'deny-model', 'actionType': 'modelInvoke',
            'resourceId': target.model, 'tenantId': 'device-local', 'effect': 'deny', 'enabled': True}))
        denied('deny-overrides-allow', gateway.execution())
        gateway.reload(lambda s: s['dataEgress'].update(modelDestinations=[]))
        denied('egress-denied', gateway.execution())
        gateway.reload(lambda s: None)
        execution = gateway.execution()
        audit = gateway.directory / 'state/audit'
        audit.rename(audit.with_name('audit-unavailable'))
        denied('required-audit-unavailable', execution, expected=503)
        return results
    finally:
        gateway.close()


def performance_probe(binary, output, key_file, target=PAI):
    gateway = Gateway(binary, output, key_file, target=target)
    key = key_file.read_text().strip()
    sampler = Sampler(output / 'resources.jsonl')
    sampler.attach('gateway', gateway.process)
    sampler.start()
    results = []
    phases = []
    result_lock = threading.Lock()
    def batch(mode, stream, round_index):
        def lane(item):
            index, count = item
            execution = gateway.execution() if mode == 'gateway' else None
            connection = gateway.connection() if mode == 'gateway' else None
            headers = {'Authorization': 'Bearer ' + gateway.token} if execution else target.headers(key)
            if execution:
                headers['x-aisp-execution-id'] = execution
            try:
                for _ in range(count):
                    if mode == 'direct':
                        connection = http.client.HTTPSConnection(target.host, 443, context=ssl.create_default_context(), timeout=30)
                    try:
                        result = call(connection, headers, stream=stream, target=target)
                        with result_lock:
                            results.append({'mode': mode, 'stream': stream, 'round': round_index, **result})
                            save(output / 'requests.json', results)
                    finally:
                        if mode == 'direct':
                            connection.close()
            finally:
                if mode == 'gateway':
                    connection.close()
                if execution:
                    gateway.control('/v1/executions/cancel', execution)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2 if stream else 1) as pool:
            list(pool.map(lane, enumerate([1, 1] if stream else [2])))
    try:
        time.sleep(1)
        execution = gateway.execution()
        gateway_call(gateway, execution)
        gateway_call(gateway, execution, stream=True)
        gateway.control('/v1/executions/cancel', execution)
        for _ in range(2):
            connection = http.client.HTTPSConnection(target.host, 443, context=ssl.create_default_context(), timeout=30)
            try:
                call(connection, target.headers(key), target=target)
            finally:
                connection.close()
        begin = time.monotonic_ns()
        for round_index in range(3):
            modes = ('direct', 'gateway') if round_index % 2 == 0 else ('gateway', 'direct')
            for stream in (False, True):
                for mode in modes:
                    phase_start = time.monotonic_ns()
                    batch(mode, stream, round_index + 1)
                    phases.append({'mode': mode, 'stream': stream, 'round': round_index + 1,
                                   'startNs': phase_start, 'endNs': time.monotonic_ns()})
        end = time.monotonic_ns()
        resources = window(sampler.rows, 'gateway', begin, end)
        quality = clock_quality(sampler.rows)
        if not quality['valid']:
            raise RuntimeError('measurement clock discontinuity')
        return {'requests': results, 'gatewayResourceWindow': resources,
                'clockQuality': quality,
                'phases': phases,
                'sampleLimitations': 'six samples per condition; direct creates TLS per request, Gateway reuses local connection per lane and default upstream pool; end-to-end comparison, not pure Gateway overhead; CPU window includes control requests and idle direct periods; not capacity/p95/p99 validation'}
    finally:
        sampler.stop()
        gateway.close()
        save(output / 'sampler.json', {'errors': sampler.errors, 'cpuSeconds': sampler.cpu_seconds})
        if sampler.errors:
            raise RuntimeError('resource sampling failed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--key-file', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--observer', type=Path)
    parser.add_argument('--phase', choices=('security', 'performance'), required=True)
    parser.add_argument('--build-profile', default='unspecified')
    parser.add_argument('--provider', choices=tuple(TARGETS), default='pai')
    args = parser.parse_args()
    target = TARGETS[args.provider]
    os.umask(0o077)
    args.out.mkdir(parents=True, exist_ok=False)
    result = {'successful': False, 'phase': args.phase, 'model': target.model, 'provider': args.provider,
              'endpoint': 'https://' + target.host + '/v1', 'binary': str(args.binary.resolve()),
              'requestOutputLimit': 32, 'buildProfile': args.build_profile, 'modelCallsPerBudget': 2,
              'maxContextsPerOwner': 16, 'requestParameters': target.payload()}
    try:
        if args.phase == 'security':
            if args.observer is None:
                raise ValueError('security probe requires an external socket observer')
            result['cases'] = security_probe(args.binary.resolve(), args.out.resolve(), args.key_file.resolve(), args.observer.resolve(), target)
        else:
            result.update(performance_probe(args.binary.resolve(), args.out.resolve(), args.key_file.resolve(), target))
        result['successful'] = True
    except Exception as error:
        # Provider error bodies and exception values can contain credentials. Keep type only.
        result['errorType'] = type(error).__name__
        if isinstance(error, CompletionError):
            result['completionFailure'] = error.state
        result['errorLocation'] = [{'file': Path(f.filename).name, 'line': f.lineno, 'function': f.name}
                                   for f in traceback.extract_tb(error.__traceback__)]
    save(args.out / 'summary.json', result)
    print(json.dumps({'successful': result['successful'], 'phase': args.phase,
                      'errorType': result.get('errorType')}))
    return 0 if result['successful'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
