#!/usr/bin/env python3
"""Exercise an Android ARM64 LLM release and its durable audit journal over ADB."""

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, closing, contextmanager
import hashlib
import http.client
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import threading
import time

from gateway_faults import Gateway, Upstream


FILE_LIMIT = "trap '' XFSZ && ulimit -f 1"
SEGMENT = re.compile(r'segment-[0-9]{20}\.jsonl')
ANDROID_EWOULDBLOCK = 11
ANDROID_EFBIG = 27
CANCEL_REQUEST = 'cancel-stream fixture'
CANCEL_EVENT = 'FIRST_EVENT_BEFORE_CLIENT_CLOSE'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


class Device:
    def __init__(self, adb, serial):
        self.command = [adb, '-s', serial] if serial else [adb, '-d']

    def run(self, *args, check=True, text=True):
        return subprocess.run(self.command + list(args), capture_output=True,
                              check=check, text=text, timeout=30)

    def shell(self, command, **kwargs):
        return self.run('shell', '-T', command, **kwargs)

    def forward(self, remote_port, cleanup):
        port = int(self.run('forward', 'tcp:0', f'tcp:{remote_port}').stdout)
        cleanup.callback(self.run, 'forward', '--remove', f'tcp:{port}')
        return port


class CancellationUpstream(Upstream):
    def chat(self, request):
        if not request.get('stream') or request['messages'][0]['content'] != CANCEL_REQUEST:
            return super().chat(request)
        self.close_connection = True
        with self.server.lock:
            self.server.calls['chat'] += 1
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Transfer-Encoding', 'chunked')
        self.end_headers()
        event = {'id': 'cancel-fixture', 'object': 'chat.completion.chunk', 'created': 1,
                 'model': 'local', 'choices': [{'index': 0, 'finish_reason': None,
                                               'delta': {'content': CANCEL_EVENT}}]}
        data = ('data: ' + json.dumps(event) + '\n\n').encode()
        self.wfile.write(f'{len(data):x}\r\n'.encode() + data + b'\r\n')
        self.wfile.flush()
        # Keep the response open until the gateway closes the upstream TCP stream.
        self.connection.settimeout(8)
        try:
            closed = self.connection.recv(1) == b''
        except ConnectionResetError:
            closed = True
        except TimeoutError:
            closed = False
        if closed:
            self.server.stream_cancelled.set()


def start_model(cleanup, handler):
    model = cleanup.enter_context(ThreadingHTTPServer(('127.0.0.1', 0), handler))
    model.daemon_threads = True
    model.lock = threading.Lock()
    model.calls = Counter()
    model.model_release = threading.Event()
    model.model_release.set()
    threading.Thread(target=model.serve_forever, daemon=True).start()
    cleanup.callback(model.shutdown)
    return model


@contextmanager
def open_response(port, method, path, body=None, token=None):
    headers = {'Host': '127.0.0.1'}
    if body is not None:
        headers['Content-Type'] = 'application/json'
    if token is not None:
        headers['Authorization'] = f'Bearer {token}'
    with closing(http.client.HTTPConnection('127.0.0.1', port, timeout=8)) as client:
        client.request(method, path, json.dumps(body) if body is not None else None, headers)
        with closing(client.getresponse()) as response:
            yield response


def request(port, method, path, body=None, token=None):
    with open_response(port, method, path, body, token) as response:
        return response.status, response.getheader('Content-Type', ''), response.read()


def invoke(port, token=None, stream=False, model='local'):
    return request(port, 'POST', '/v1/chat/completions', {
        'model': model, 'messages': [{'role': 'user', 'content': 'audit fixture'}],
        'stream': stream,
    }, token)


def audit_status(port):
    status, _, body = request(port, 'GET', '/api/security/audit')
    require(status == 200, f'audit status returned HTTP {status}')
    return json.loads(body)


@contextmanager
def gateway_process(device, command, directory, log, admin, limited=False, readiness_port=None):
    pid_file = shlex.quote(f'{directory}/{log.stem}.pid')
    prefix = f'{FILE_LIMIT} && ' if limited else ''
    start = f'umask 077 && echo "$$" > {pid_file} && {prefix}exec {command}'
    with log.open('wb') as output:
        process = subprocess.Popen(device.command + ['shell', '-T', start],
                                   stdout=output, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 15
            interval = .025 if readiness_port is not None else .15
            while process.poll() is None and time.monotonic() < deadline:
                try:
                    if readiness_port is not None and request(readiness_port, 'GET', '/healthz/ready')[0] != 200:
                        time.sleep(interval)
                        continue
                    state = audit_status(admin)
                except (OSError, http.client.HTTPException):
                    time.sleep(interval)
                    continue
                require(state['persistenceHealthy'], 'gateway started with unhealthy persistence')
                break
            else:
                raise RuntimeError(f'gateway failed to start, see {log}')
            yield
        finally:
            if process.poll() is None:
                try:
                    device.shell(f'if test -s {pid_file}; then kill -TERM "$(cat {pid_file})"; fi')
                    process.wait(timeout=15)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=5)
    require(process.returncode == 0, f'gateway exited {process.returncode}, see {log}')


def snapshot(device, directory):
    names = device.shell(f'ls -1 {shlex.quote(directory)}').stdout.splitlines()
    require(names and all(name == 'writer.jsonl' or SEGMENT.fullmatch(name) for name in names),
            f'unexpected test journal files: {names}')
    return {name: device.shell(shlex.join(['cat', f'{directory}/{name}']), text=False).stdout
            for name in names}


def audit_records(files):
    return [json.loads(line) for name, data in sorted(files.items()) if SEGMENT.fullmatch(name)
            for line in data.splitlines()]


def record_sequences(files):
    records = audit_records(files)
    sequences = [record['sequence'] for record in records]
    require(sequences and sequences == list(range(sequences[0], sequences[-1] + 1))
            and all(row['event']['sequence'] == row['sequence'] for row in records),
            'persisted event sequences are not contiguous or do not match their envelopes')
    return sequences


def check_smoke(device, launch, fixture, model, llm, logs, evidence):
    duplicate = device.shell(launch, check=False)
    (logs / 'second-writer.log').write_text(duplicate.stdout + duplicate.stderr)
    require(duplicate.returncode != 0 and f'os error {ANDROID_EWOULDBLOCK}' in duplicate.stderr,
            'second gateway did not report audit lock contention')
    denied = [invoke(llm)[0], invoke(llm, fixture.token(tenant='tenant-b'))[0]]
    require(denied == [401, 403] and model.calls['chat'] == 0,
            f'identity denial mismatch: statuses={denied}, upstream={model.calls["chat"]}')
    token = fixture.token(user='android-audit-' + 'x' * 4000)
    with ThreadPoolExecutor(max_workers=4) as pool:
        replies = list(pool.map(lambda _: invoke(llm, token), range(8)))
    require(all(status == 200 and json.loads(body)['choices'][0]['message']['content'] == 'ok'
                for status, _, body in replies), 'authenticated concurrent requests failed')
    status, content_type, body = invoke(llm, token, stream=True)
    require(status == 200 and 'text/event-stream' in content_type
            and b'BEFORE_REVOCATION' in body and b'AFTER_REVOCATION' in body,
            'SSE did not deliver both fixture events')
    require(model.calls['chat'] == 9, 'upstream did not see exactly the nine admitted requests')
    evidence['smoke'] = {'secondWriterRejected': True, 'deniedStatuses': denied,
                         'deniedUpstreamCalls': 0, 'successfulConcurrentRequests': 8,
                         'streamStatus': status}
    return token


def check_model_security(device, directory, model, blocked, llm, token, evidence):
    before = model.calls['chat'], blocked.calls['chat']
    cases = [('model', 'blocked-model', model.server_port), ('egress', 'blocked-egress', blocked.server_port)]
    for name, requested_model, port in cases:
        status, _, body = invoke(llm, token, model=requested_model)
        require(status == 403 and body == b'authorization failed',
                f'{name} denial returned HTTP {status}: {body!r}')
        require((model.calls['chat'], blocked.calls['chat']) == before,
                f'{name} denial reached a test upstream')
        events = (row['event'] for row in audit_records(snapshot(device, directory)))
        decision = next((event for event in events if event['kind'] == 'authorization'
                         and event['action'] == 'ModelInvoke:invoke' and event['decision'] == 'deny'
                         and (event['policyId'] or '').startswith('routing:candidate:attempt:')
                         and event['resourceId'] == requested_model), None)
        require(decision is not None, f'{name} denial did not record candidate rejection for {requested_model}')
        evidence[name] = {'status': status, 'upstreamCalls': 0, 'auditPolicy': decision['policyId'],
                          'auditResource': requested_model, 'configuredDestination': f'localhost:{port}'}

    payload = {'model': 'local', 'messages': [{'role': 'user', 'content': CANCEL_REQUEST}], 'stream': True}
    with open_response(llm, 'POST', '/v1/chat/completions', payload, token) as response:
        require(response.status == 200 and 'text/event-stream' in response.getheader('Content-Type', ''),
                f'cancellation fixture did not receive an SSE stream: HTTP {response.status}')
        require(CANCEL_EVENT.encode() in response.readline(), 'client did not receive the first SSE event')
    require(model.stream_cancelled.wait(6), 'upstream socket stayed open after the SSE client disconnected')
    require(model.calls['chat'] == before[0] + 1 and blocked.calls['chat'] == before[1],
            'cancellation retried or dispatched the stream to an unexpected upstream')
    status, _, _ = invoke(llm, token)
    require(status == 200 and model.calls['chat'] == before[0] + 2,
            'authorized request did not succeed after stream cancellation')
    evidence['cancellation'] = {'firstEventReceived': True, 'upstreamSocketClosed': True,
                                'streamUpstreamCalls': 1, 'subsequentRequestStatus': status}


def check_audit(device, launch, directory, fixture, upstreams, llm, admin, logs, evidence):
    remote_audit = f'{directory}/audit'
    model, blocked = upstreams
    with gateway_process(device, launch, directory, logs / 'gateway-baseline.log', admin):
        token = check_smoke(device, launch, fixture, model, llm, logs, evidence)
        check_model_security(device, remote_audit, model, blocked, llm, token,
                             evidence.setdefault('modelSecurity', {}))
        baseline = snapshot(device, remote_audit)
        sequences = record_sequences(baseline)
        next_sequence = audit_status(admin)['capacity']['nextSequence']
        require(next_sequence == sequences[-1] + 1, 'status differs from persisted audit tail')

    limits = device.shell(f'{FILE_LIMIT} && cat /proc/self/limits').stdout
    limit = re.search(r'^Max file size\s+(\d+)\s+', limits, re.MULTILINE)
    require(limit is not None, 'could not establish a file size limit on the device')
    limit_bytes = int(limit[1])
    last_segment = max(name for name in baseline if SEGMENT.fullmatch(name))
    require(len(baseline[last_segment]) >= limit_bytes,
            'audit segment must already be at or beyond the limit to trigger a zero-byte write failure')
    before = model.calls['chat']
    fault_log = logs / 'gateway-fault.log'
    with gateway_process(device, launch, directory, fault_log, admin, limited=True):
        require(audit_status(admin)['capacity']['nextSequence'] == next_sequence,
                'restart under the file size limit did not replay the existing journal')
        denied = [invoke(llm, token)[0] for _ in range(2)]
        fault = audit_status(admin)
        require(all(status in (403, 503) for status in denied) and model.calls['chat'] == before,
                f'required audit fault did not fail closed: {denied}, upstream delta={model.calls["chat"] - before}')
        require(fault['capacity']['state'] == 'failed' and not fault['persistenceHealthy']
                and fault['persistenceFailures'] > 0 and fault['capacity']['nextSequence'] == next_sequence,
                f'audit journal did not quarantine without advancing its sequence: {fault}')
        require(snapshot(device, remote_audit) == baseline, 'the fault modified stored evidence')
    require(f'os error {ANDROID_EFBIG}' in fault_log.read_text(errors='replace'),
            'gateway did not report a kernel file-size write error')
    evidence['writeFailure'] = {'errno': ANDROID_EFBIG, 'fileLimitBytes': limit_bytes,
                                'statuses': denied, 'upstreamCalls': 0, 'journalStatus': fault,
                                'originalFilesUnchanged': True}

    with gateway_process(device, launch, directory, logs / 'gateway-recovery.log', admin):
        require(audit_status(admin)['capacity']['nextSequence'] == next_sequence
                and snapshot(device, remote_audit) == baseline,
                'restart did not recover the exact journal and its next sequence')
        status, _, body = invoke(llm, token)
        require(status == 200 and model.calls['chat'] == before + 1, f'recovered request failed: {status}, {body!r}')
        recovered = snapshot(device, remote_audit)
        after_sequences = record_sequences(recovered)
        require(all(recovered.get(name, b'').startswith(data) for name, data in baseline.items())
                and after_sequences[:len(sequences)] == sequences and len(after_sequences) > len(sequences),
                'recovery did not preserve prior evidence and append new audit records')
        after = audit_status(admin)
        require(after['persistenceHealthy'] and after['capacity']['nextSequence'] == after_sequences[-1] + 1,
                f'recovered status disagrees with the new journal tail: {after}')
    evidence['recovery'] = {'status': status, 'upstreamCalls': 1, 'recordsPreserved': len(sequences),
                            'nextSequenceBefore': next_sequence, 'nextSequenceAfter': after_sequences[-1] + 1}


def run_acceptance(device, binary, logs, evidence, worker_threads=None):
    with binary.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    evidence['binarySha256'] = digest
    with ExitStack() as cleanup:
        directory = device.shell('umask 077 && mktemp -d /data/local/tmp/asp-embedded-audit.XXXXXX').stdout.strip()
        require(re.fullmatch(r'/data/local/tmp/asp-embedded-audit\.[a-zA-Z0-9]+', directory),
                'ADB did not return a dedicated test directory')
        cleanup.callback(device.shell, shlex.join(['rm', '-rf', directory]))
        remote_binary = f'{directory}/ai-security-platform'
        remote_config = f'{directory}/gateway.json'
        evidence['device'] = dict(zip(('model', 'api', 'uid'), device.shell(
            'getprop ro.product.model; getprop ro.build.version.sdk; id -u').stdout.splitlines(), strict=True))
        device.run('push', str(binary), remote_binary)
        device.shell(f'umask 077 && mkdir {directory}/audit && chmod 700 {remote_binary}')
        expected = device.shell(f'toybox sha256sum {remote_binary}').stdout.split()[0]
        require(expected == digest, 'device binary digest differs from the input release')
        version = json.loads(device.shell(f'{remote_binary} --version').stdout)
        require(version.get('build_target') == 'aarch64-linux-android' and version.get('build_profile') == 'release',
                f'expected an Android ARM64 Release binary: {version}')
        evidence['buildInfo'] = version

        model = start_model(cleanup, CancellationUpstream)
        model.stream_cancelled = threading.Event()
        blocked = start_model(cleanup, Upstream)
        fixture = Gateway(str(binary), logs, model.server_port, llm_only=True)
        fixture.role_ports.close()
        cleanup.callback(fixture.signer.close)
        config = json.loads(fixture.config.read_text())
        config['config'].update(bindAddress='127.0.0.1', management={'mode': 'diagnostic'},
                                dns={'lookupFamily': 'V4Only'}, securityAudit={'directory': f'{directory}/audit'})
        if worker_threads is not None:
            config['config']['workerThreads'] = worker_threads
            evidence['configuredWorkerThreads'] = worker_threads
        system = config['aiSystems'][0]
        model_host = f'localhost:{model.server_port}'
        system['llm']['models'][0]['params']['baseUrl'] = f'http://{model_host}/v1'
        system['llm']['models'].extend([
            {'name': 'blocked-model', 'provider': 'openAI', 'params': {'baseUrl': f'http://{model_host}/v1'}},
            {'name': 'blocked-egress', 'provider': 'openAI',
             'params': {'baseUrl': f'http://localhost:{blocked.server_port}/v1'}},
        ])
        system['security']['policies'].append({'id': 'deny-fixture-model', 'tenantId': 'tenant-a',
                                              'actionType': 'modelInvoke', 'resourceId': 'blocked-model',
                                              'effect': 'deny', 'enabled': True})
        system['security'].update(requiredAudit={'actionTypes': ['modelInvoke']},
                                  requiredIdentity={'user': True, 'tenant': True, 'agent': False},
                                  dataEgress={'classification': 'internal', 'modelDestinations': [model_host]})
        fixture.config.write_text(json.dumps(config))
        device.run('push', str(fixture.config), remote_config)
        launch = shlex.join([remote_binary, '--file', remote_config])
        validation = device.shell(f'{launch} --validate-only', check=False)
        (logs / 'validate.log').write_text(validation.stdout + validation.stderr)
        require(validation.returncode == 0 and 'Configuration is valid!' in validation.stdout,
                'device configuration validation failed, see validate.log')

        for server in (model, blocked):
            upstream = f'tcp:{server.server_port}'
            device.run('reverse', '--no-rebind', upstream, upstream)
            cleanup.callback(device.run, 'reverse', '--remove', upstream)
        llm = device.forward(fixture.model_port, cleanup)
        admin = device.forward(fixture.role_ports.ports['admin'], cleanup)
        check_audit(device, launch, directory, fixture, (model, blocked), llm, admin, logs, evidence)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', default='adb', help='ADB executable, defaults to adb on PATH')
    parser.add_argument('--serial', help='ADB device serial, defaults to the sole USB device')
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--worker-threads', type=int, help='verify a gateway data-plane worker setting')
    args = parser.parse_args()
    os.umask(0o077)
    if not args.binary.is_file():
        parser.error('--binary must be an existing file')
    if args.worker_threads is not None and args.worker_threads < 1:
        parser.error('--worker-threads must be positive')
    logs = args.report.with_name(args.report.name + '.logs')
    if args.report.exists() or logs.exists():
        parser.error('report and logs must use a new path')
    logs.mkdir(parents=True)
    report = {'successful': False}
    try:
        run_acceptance(Device(args.adb, args.serial), args.binary.resolve(), logs, report, args.worker_threads)
        report['successful'] = True
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        with args.report.open('x') as output:
            json.dump(report, output, indent=2)
            output.write('\n')
    print(f'PASS: Android LLM smoke, model and egress policy, SSE cancellation, and durable audit; {args.report}')


if __name__ == '__main__':
    main()
