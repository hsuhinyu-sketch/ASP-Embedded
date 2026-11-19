#!/usr/bin/env python3
"""Offline local composition: real Gateway + read-only loopback Tool; deterministic model fixture."""
import argparse
import base64
import copy
import http.server
import json
import os
from pathlib import Path
import platform
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'examples/edge'))
import local_assistant as edge

BINARY = None
ARTIFACTS = None


class Model(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        self.server.requests.append(request)
        body = json.dumps({'id': 'local', 'object': 'chat.completion', 'created': 1,
            'model': 'fixture', 'choices': [{'index': 0, 'finish_reason': 'stop',
            'message': {'role': 'assistant', 'content': 'Local device evidence received.'}}]}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class EdgeLocal(unittest.TestCase):
    evidence = {}

    def setUp(self):
        self.directory = Path(tempfile.mkdtemp(prefix='edge-', dir=ARTIFACTS))
        self.state = self.directory / 'state'
        self.model = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Model)
        self.model.requests = []
        self.thread = threading.Thread(target=self.model.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_model)
        reserved = [socket.socket(), socket.socket(), socket.socket()]
        for sock in reserved:
            sock.bind(('127.0.0.1', 0))
            self.addCleanup(sock.close)
        self.llm_port, self.mcp_port, self.tool_port = [sock.getsockname()[1] for sock in reserved]
        self.config = edge.provision(self.state, 'fixture', f'http://127.0.0.1:{self.model.server_port}/v1',
                                     self.llm_port, self.mcp_port, self.tool_port)
        self.token = (self.state / 'caller.jwt').read_text()
        self.process = None
        self.log = (self.directory / 'gateway.log').open('w')
        self.addCleanup(self.close_gateway)
        for sock in reserved:
            sock.close()
        self.tool_process = subprocess.Popen([sys.executable,
            str(Path(edge.__file__).with_name('device_tools.py')), '--port', str(self.tool_port)],
            stdout=self.log, stderr=subprocess.STDOUT)
        self.addCleanup(self.close_tools)

    def close_tools(self):
        self.tool_process.terminate()
        self.tool_process.wait(5)

    def close_model(self):
        self.model.shutdown()
        self.model.server_close()
        self.thread.join(5)

    def close_gateway(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(5)
        self.log.close()

    def start(self):
        (self.state / 'gateway.json').write_text(json.dumps(self.config))
        ready_read, ready_write = os.pipe()
        try:
            self.process = subprocess.Popen([BINARY, '--file', str(self.state / 'gateway.json')],
                stdout=self.log, stderr=subprocess.STDOUT, pass_fds=(ready_write,),
                env=dict(os.environ, READY_FD=str(ready_write),
                         RUST_LOG='info,ai_security_platform_runtime::state_manager=debug'))
        finally:
            os.close(ready_write)
        try:
            if not select.select([ready_read], [], [], 30)[0] or os.read(ready_read, 1) != b'':
                self.fail('Gateway READY_FD timeout')
            self.assertIsNone(self.process.poll(), (self.directory / 'gateway.log').read_text()[-6000:])
        finally:
            os.close(ready_read)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.fail((self.directory / 'gateway.log').read_text()[-6000:])
            try:
                for port in (self.llm_port, self.mcp_port, self.tool_port):
                    with socket.create_connection(('127.0.0.1', port), timeout=.2):
                        pass
                return
            except OSError:
                time.sleep(.05)
        self.fail('local Gateway did not start')

    def client(self, token=None):
        return edge.Client(f'http://127.0.0.1:{self.llm_port}', f'http://127.0.0.1:{self.mcp_port}',
                           self.token if token is None else token, timeout=10)

    def begin(self):
        client = self.client()
        client.execution = client.control('/v1/executions', {})['executionId']
        headers, _ = client.rpc('initialize', {'protocolVersion': '2025-11-25', 'capabilities': {},
            'clientInfo': {'name': 'edge-regression', 'version': '1'}})
        client.session = headers['mcp-session-id']
        client.rpc('notifications/initialized')
        _, tools = client.rpc('tools/list')
        name = next(t['name'] for t in tools['tools'] if t['name'] in ('device_info', 'device_device_info'))
        return client, name

    def signed(self, **overrides):
        header, body, _ = self.token.split('.')
        claims = json.loads(base64.urlsafe_b64decode(body + '=' * (-len(body) % 4)))
        claims.update(overrides)
        message = (header + '.' + edge.b64(json.dumps(claims).encode())).encode()
        return message.decode() + '.' + edge.b64(edge.ed25519((self.state / 'issuer.key').read_bytes(), message))

    def test_readonly_tool_model_chain_and_loopback_listeners(self):
        self.start()
        result = self.client().answer('Describe the operating system and architecture.', 'fixture')
        self.assertEqual(result['tool'], 'device_info')
        self.assertEqual(len(self.model.requests), 1)
        prompt = json.loads(self.model.requests[0]['messages'][-1]['content'])
        device = prompt['device']
        self.assertEqual(device['architecture'], platform.machine())
        self.assertEqual(device['system'], platform.system())
        listeners = []
        for row in Path(f'/proc/{self.process.pid}/net/tcp').read_text().splitlines()[1:]:
            fields = row.split()
            address, port = fields[1].split(':')
            if fields[3] == '0A' and int(port, 16) in (self.llm_port, self.mcp_port):
                listeners.append(address)
        self.assertEqual(listeners, ['0100007F', '0100007F'])
        events = [json.loads(line)['event'] for p in (self.state / 'audit').glob('segment-*.jsonl')
                  for line in p.read_text().splitlines()]
        required = {event['policyId'] for event in events if event['decision'] == 'allow'}
        for policy in ('audit:required:device-info', 'audit:required:model', 'audit:required:execution/create'):
            self.assertIn(policy, required)
        self.evidence[self.id()] = {'realReadOnlyTool': True, 'modelCalls': 1, 'loopbackOnly': True,
                                   'requiredAuditPersisted': True}

    def test_missing_foreign_and_expired_identity_never_reach_model(self):
        self.start()
        for token in ('', self.signed(tenant_id='foreign'), self.signed(exp=int(time.time()) - 60)):
            with self.subTest(tokenKind='invalid identity'), self.assertRaises(edge.EdgeError):
                self.client(token).answer('Describe this device.', 'fixture')
        self.assertEqual(self.model.requests, [])

    def test_unknown_tool_and_invalid_arguments_are_rejected(self):
        self.start()
        client, _ = self.begin()
        invocation = client.control('/v1/executions/invocations',
            {'server': 'device', 'tool': 'shell', 'arguments': {}})['invocationId']
        with self.assertRaises(edge.EdgeError):
            client.rpc('tools/call', {'name': 'shell', 'arguments': {}}, invocation=invocation)
        # The actual Tool server independently rejects caller-selected commands.
        from device_tools import handle
        with self.assertRaises(ValueError):
            handle({'method': 'tools/call', 'params': {'name': 'device_info', 'arguments': {'command': 'id'}}})
        self.assertEqual(self.model.requests, [])

    def test_tool_invocation_cannot_be_replayed(self):
        self.start()
        client, name = self.begin()
        invocation = client.control('/v1/executions/invocations',
            {'server': 'device', 'tool': 'device_info', 'arguments': {}})['invocationId']
        client.rpc('tools/call', {'name': name, 'arguments': {}}, invocation=invocation)
        with self.assertRaises(edge.EdgeError):
            client.rpc('tools/call', {'name': name, 'arguments': {}}, invocation=invocation)
        self.assertEqual(self.model.requests, [])

    def test_cancelled_execution_cannot_invoke_model(self):
        self.start()
        client = self.client()
        client.execution = client.control('/v1/executions', {})['executionId']
        client.control('/v1/executions/cancel', {})
        with self.assertRaises(edge.EdgeError):
            client.control('/v1/chat/completions', {'model': 'fixture', 'messages': [{'role': 'user', 'content': 'hi'}]})
        self.assertEqual(self.model.requests, [])

    def test_security_reload_invalidates_live_execution_and_keeps_default_deny(self):
        self.start()
        client = self.client()
        client.execution = client.control('/v1/executions', {})['executionId']
        changed = copy.deepcopy(self.config)
        changed['aiSystems'][0]['security']['policies'] = [p for p in changed['aiSystems'][0]['security']['policies']
                                                        if p['id'] != 'model']
        replacement = self.state / 'candidate.json'
        replacement.write_text(json.dumps(changed))
        replacement.replace(self.state / 'gateway.json')
        deadline = time.monotonic() + 10
        while 'Config reloaded successfully' not in (self.directory / 'gateway.log').read_text():
            self.assertIsNone(self.process.poll())
            if time.monotonic() > deadline:
                self.fail('security reload was not published')
            time.sleep(.05)
        for current in (client, self.client()):
            if current.execution is None:
                current.execution = current.control('/v1/executions', {})['executionId']
            with self.assertRaises(edge.EdgeError):
                current.control('/v1/chat/completions', {'model': 'fixture', 'messages': [{'role': 'user', 'content': 'hi'}]})
        self.assertEqual(self.model.requests, [])

    def test_required_audit_storage_failure_prevents_model_dispatch(self):
        self.start()
        client = self.client()
        client.execution = client.control('/v1/executions', {})['executionId']
        (self.state / 'audit').rename(self.state / 'audit-unavailable')
        with self.assertRaises(edge.EdgeError):
            client.control('/v1/chat/completions', {'model': 'fixture', 'messages': [{'role': 'user', 'content': 'hi'}]})
        self.assertEqual(self.model.requests, [])

    def test_native_pii_masks_question_before_local_model_receives_it(self):
        self.start()
        self.client().answer('Contact alice@example.com and describe this device.', 'fixture')
        wire = json.dumps(self.model.requests)
        self.assertNotIn('alice@example.com', wire)
        self.assertIn('[EMAIL_ADDRESS]', wire)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    BINARY = str(Path(args.binary).resolve())
    ARTIFACTS = Path(tempfile.mkdtemp(prefix='local-edge-', dir=args.report.parent))
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(EdgeLocal))
    args.report.write_text(json.dumps({'successful': result.wasSuccessful(), 'testsRun': result.testsRun,
        'errors': [str(t) for t, _ in result.errors], 'failures': [str(t) for t, _ in result.failures],
        'skipped': [str(t) for t, _ in result.skipped], 'scenarios': EdgeLocal.evidence,
        'artifacts': str(ARTIFACTS)}, indent=2) + '\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
