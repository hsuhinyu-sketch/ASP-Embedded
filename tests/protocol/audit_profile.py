#!/usr/bin/env python3
"""Managed audit capacity, retention and offline export through the real LLM gateway."""
import argparse
import http.client
import http.server
import json
import os
from pathlib import Path
import resource
import subprocess
import tempfile
import threading
import time
import unittest

import gateway_faults

BINARY = None


class Model(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        self.rfile.read(int(self.headers['Content-Length']))
        self.server.calls += 1
        body = json.dumps({'id': 'audit-fixture', 'object': 'chat.completion', 'created': 1,
            'model': 'local', 'choices': [{'index': 0, 'finish_reason': 'stop',
            'message': {'role': 'assistant', 'content': 'OK'}}]}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Audit(unittest.TestCase):
    evidence = {}

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='audit-acceptance-')
        self.directory = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.model = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Model)
        self.model.calls = 0
        self.thread = threading.Thread(target=self.model.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_model)
        self.gateway = gateway_faults.Gateway(BINARY, self.directory, self.model.server_port, llm_only=True)
        self.gateway.scenario = self.id()
        if self.gateway.artifacts is not None:
            self.gateway.artifacts /= self.id().rsplit('.', 1)[-1]
        self.addCleanup(self.gateway.signer.close)
        self.addCleanup(self.gateway.stop)
        self.config = json.loads(self.gateway.config.read_text())
        self.config['config']['management'] = {'mode': 'diagnostic'}
        self.audit = self.directory / 'audit'
        self.audit.mkdir(mode=0o700)
        self.config['config']['securityAudit'] = {'directory': str(self.audit),
            'maxSegmentBytes': 1048576, 'maxSegments': 2, 'retentionSeconds': 3600}
        self.config['aiSystems'][0]['security']['requiredAudit'] = {'actionTypes': ['modelInvoke']}
        # Large synthetic opaque subject reaches the minimum legal segment capacity quickly.
        # Normal JWT verification and the existing event byte bound still apply.
        self.token = self.gateway.token(user='audit-fixture-' + 'x' * 4000)

    def close_model(self):
        self.model.shutdown()
        self.model.server_close()
        self.thread.join(5)

    def start(self):
        self.gateway.config.write_text(json.dumps(self.config))
        self.gateway.start()

    def status(self, host='127.0.0.1', method='GET'):
        connection = http.client.HTTPConnection('127.0.0.1', self.gateway.role_ports.ports['admin'], timeout=6)
        try:
            connection.request(method, '/api/security/audit', headers={'Host': host})
            reply = connection.getresponse()
            return reply.status, reply.read()
        finally:
            connection.close()

    def generate(self):
        connection = http.client.HTTPConnection('127.0.0.1', self.gateway.model_port, timeout=6)
        try:
            connection.request('POST', '/v1/chat/completions', json.dumps({'model': 'local',
                'messages': [{'role': 'user', 'content': 'safe fixture request'}], 'stream': False}),
                {'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'})
            reply = connection.getresponse()
            return reply.status, reply.read()
        finally:
            connection.close()

    def stored(self):
        return {f.name: f.read_bytes() for f in self.audit.iterdir()}

    def test_status_without_ui_preserves_management_exposure_policy(self):
        self.config['config']['management']['mode'] = 'edge'
        self.start()
        self.assertEqual(self.status()[0], 403)
        self.gateway.stop()
        self.config['config']['management']['mode'] = 'diagnostic'
        self.start()
        status, raw = self.status()
        self.assertEqual(status, 200, raw)
        value = json.loads(raw)
        self.assertTrue(value['persistenceEnabled'])
        self.assertEqual(value['capacity']['state'], 'ready')
        self.assertEqual(value['capacity']['maximumBytes'], 2097152)
        for forbidden in [b'writer.jsonl', str(self.audit).encode(), b'tenant-a', b'audit-fixture-']:
            self.assertNotIn(forbidden, raw)
        self.assertEqual(self.status('remote.example')[0], 403)
        self.assertEqual(self.status(method='POST')[0], 403)

    def test_capacity_warns_preserves_evidence_and_recovers_after_retention(self):
        self.config['config']['securityAudit']['retentionSeconds'] = 5
        self.start()
        for _ in range(512):
            status, body = self.generate()
            if status != 200:
                self.assertIn(status, (403, 503), body)
                break
        else:
            self.fail('bounded audit capacity did not exhaust')
        state = json.loads(self.status()[1])
        self.assertEqual(state['capacity']['state'], 'exhausted')
        self.assertFalse(state['persistenceHealthy'])
        next_sequence = state['capacity']['nextSequence']
        before = self.stored()
        calls = self.model.calls
        self.assertIn(self.generate()[0], (403, 503))
        self.assertEqual(self.model.calls, calls)
        after = self.stored()
        for name, data in before.items():
            self.assertTrue(after[name].startswith(data), 'unexpired evidence was overwritten')
        log = (self.directory / 'gateway.log').read_text()
        self.assertEqual(log.count('security audit capacity high;'), 1)
        deadline = state['capacity']['nextReclaimAtMillis'] / 1000
        time.sleep(max(0, deadline - time.time()) + .05)
        self.assertEqual(self.generate()[0], 200)
        self.assertEqual(self.model.calls, calls + 1)
        recovered = json.loads(self.status()[1])
        self.assertTrue(recovered['persistenceHealthy'])
        self.assertGreater(recovered['capacity']['nextSequence'], next_sequence)
        rows = [json.loads(line) for path in sorted(self.audit.glob('segment-*.jsonl')) for line in path.read_text().splitlines()]
        for row in rows:
            self.assertEqual(row['sequence'], row['event']['sequence'])
        self.assertTrue(all(b['sequence'] == a['sequence'] + 1 for a, b in zip(rows, rows[1:])))
        self.evidence[self.id()] = {'blockedPeerDelta': 0, 'recovered': True,
            'nextSequenceBefore': next_sequence, 'nextSequenceAfter': recovered['capacity']['nextSequence']}

    def test_real_persistence_fault_stays_closed_after_permissions_are_repaired(self):
        self.start()
        self.assertEqual(self.generate()[0], 200)
        segment = next(self.audit.glob('segment-*.jsonl'))
        segment.chmod(0o644)
        before = self.model.calls
        self.assertIn(self.generate()[0], (403, 503))
        self.assertEqual(json.loads(self.status()[1])['capacity']['state'], 'failed')
        segment.chmod(0o600)
        self.assertIn(self.generate()[0], (403, 503))
        self.assertEqual(self.model.calls, before)
        self.assertEqual(json.loads(self.status()[1])['capacity']['state'], 'failed')

    def test_offline_cli_export_is_exclusive_byte_preserving_and_does_not_release_source_capacity(self):
        self.start()
        self.assertEqual(self.generate()[0], 200)
        output = self.directory / 'archive'
        command = [BINARY, 'export-audit', '--file', str(self.gateway.config), '--output', str(output)]
        live = subprocess.run(command, capture_output=True, timeout=15)
        self.assertNotEqual(live.returncode, 0)
        self.assertFalse(output.exists())
        self.assertEqual(self.generate()[0], 200)
        self.gateway.stop()
        before = self.stored()
        # Offline tooling must share the Gateway's environment expansion semantics.
        self.config['config']['securityAudit']['directory'] = '${AISP_AUDIT_EXPORT_SOURCE}'
        self.gateway.config.write_text(json.dumps(self.config))
        export_environment = dict(os.environ, AISP_AUDIT_EXPORT_SOURCE=str(self.audit))
        partial = self.directory / 'partial-archive'
        def limit_export_file():
            resource.setrlimit(resource.RLIMIT_FSIZE, (1024, 1024))
        failed = subprocess.run(command[:-1] + [str(partial)], capture_output=True,
                                timeout=15, preexec_fn=limit_export_file, env=export_environment)
        self.assertNotEqual(failed.returncode, 0)
        self.assertFalse((partial / 'manifest.json').exists())
        self.assertEqual(self.stored(), before, 'failed archive write changed source evidence')
        exported = subprocess.run(command, capture_output=True, timeout=15, env=export_environment)
        self.assertEqual(exported.returncode, 0, exported.stderr)
        self.assertEqual(self.stored(), before)
        manifest = json.loads((output / 'manifest.json').read_text())
        for file in manifest['files']:
            self.assertEqual((output / file['name']).read_bytes(), before[file['name']])
        self.assertNotEqual(subprocess.run(command, capture_output=True, timeout=15, env=export_environment).returncode, 0)
        self.config['config']['securityAudit']['directory'] = str(self.audit)
        self.gateway.config.write_text(json.dumps(self.config))
        self.gateway.start()
        self.assertEqual(self.generate()[0], 200)
        self.assertGreater(json.loads(self.status()[1])['capacity']['nextSequence'], manifest['lastSequence'] + 1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=lambda p: str(Path(p).resolve()))
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    BINARY = args.binary
    gateway_faults.ARTIFACTS = args.report.with_suffix('.gateway')
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Audit))
    args.report.write_text(json.dumps({'successful': result.wasSuccessful(), 'testsRun': result.testsRun,
        'errors': [str(t) for t, _ in result.errors], 'failures': [str(t) for t, _ in result.failures],
        'skipped': [str(t) for t, _ in result.skipped], 'evidence': Audit.evidence}, indent=2) + '\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
