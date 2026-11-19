#!/usr/bin/env python3
"""Joint Context/document SQLite through MCP, LLM and durable A2A business paths."""
import argparse
import copy
import http.client
import json
from pathlib import Path
import subprocess
import uuid
import threading
import time
import unittest

import gateway_faults
import rag_profile
from workflow_durable_profile import DurableWorkflow


class SqliteWorkflow(DurableWorkflow):
    evidence = {}

    def setUp(self):
        super().setUp()
        if self.gateway.artifacts is not None:
            self.gateway.artifacts /= self.id().rsplit('.', 1)[-1]
        self.legacy_security = copy.deepcopy(self.system['security'])
        self.legacy_documents = copy.deepcopy(self.system['rag']['lifecycle'])
        flow = self.system['security']['crossComponent']
        flow.pop('storage')
        flow['sqlite'] = {
            'path': str(self.directory / 'rag.sqlite'), 'namespace': flow['namespace'],
            'maxContexts': flow.get('maxContexts', 1024), 'maxDocuments': self.legacy_documents['maxDocuments'],
            'maxDatabaseBytes': 1048576, 'busyTimeoutMillis': 100,
        }
        self.system['rag'].pop('lifecycle')

    def test_sqlite_context_composes_with_inference_parameters(self):
        self.system['inference'] = {'parameters': {'overrides': {'temperature': 0.25}}}
        context, retrieved = self.begin()
        self.assertEqual(self.generate(context, retrieved)[0], 200)
        self.assertEqual(self.model.requests[0][2]['temperature'], 0.25)

    def test_sqlite_context_controls_durable_agent_event_recovery(self):
        security = self.system['security']
        security['a2aObjects']['eventRecovery'] = {'namespace': self.system['name'],
            'storage': {'path': str(self.directory / 'agent-events.jsonl'), 'maxBytes': 16777216}}
        security['policies'].append(self.allow('agentEventRecover'))
        context, _ = self.begin()
        self.agent.mode = 'hold'
        self.agent.release, self.agent.stream_started = threading.Event(), threading.Event()
        self.agent.release.set()
        message = {'kind': 'message', 'role': 'user', 'messageId': 'recoverable',
                   'parts': [{'kind': 'text', 'text': 'business evidence'}]}
        status, _, wire = self.call(self.agent_port, '/agent', {'jsonrpc': '2.0', 'id': 1,
            'method': 'message/stream', 'params': {'message': message}}, context,
            extra={'Accept': 'text/event-stream'})
        self.assertEqual(status, 200, wire)
        cursors = [line[3:].strip().decode() for line in wire.splitlines() if line.startswith(b'id:')]
        self.assertGreaterEqual(len(cursors), 2, wire)
        self.assertNotIn(b'AFTER-FINAL-MARKER', wire)
        status, _, recovered = self.agent_rpc('aisp.events/read', {'id': 'task-1', 'after': cursors[0], 'limit': 16}, context)
        self.assertEqual(status, 200, recovered)
        batch = json.loads(recovered)['result']
        self.assertEqual(batch['scope'], 'gateway-observed')
        self.assertTrue(batch['events'])
        self.assertNotIn(b'private artifact', recovered)
        before = self.agent.calls.copy()
        self.assertEqual(self.revoke(context)[0], 200)
        self.assertIn(self.agent_rpc('aisp.events/read', {'id': 'task-1', 'after': cursors[0], 'limit': 16}, context)[0], (400, 403))
        self.assertEqual(self.agent.calls, before)

    def sampling_task(self):
        from sampling_profile import SamplingUpstream
        self.tool.RequestHandlerClass = SamplingUpstream
        self.tool.answers, self.tool.model_requests, self.tool.sampling_changes = [], [], {}
        for name in ['answered', 'model_started', 'model_release']:
            setattr(self.tool, name, threading.Event())
        self.tool.model_release.set()
        self.tool.model_status = 200
        security = self.system['security']
        security['executionBudget'] = {'namespace': str(uuid.uuid4()), 'maxModelCalls': 1,
            'maxToolCalls': 1, 'maxAttempts': 32, 'maxConcurrent': 4}
        security['mcpSessions'].update({'reauthorizeSeconds': 1,
            'reverse': {'samplingModels': ['local'], 'timeoutSeconds': 3},
            'tasks': {'tools': ['echo'], 'sampling': {'authority': f'127.0.0.1:{self.gateway.model_port}',
                'path': '/v1/chat/completions', 'model': 'local'}}})
        security['policies'] += [self.allow('executionOperation'), self.allow('mcpTaskOperation')]
        context, _ = self.begin()
        status, _, wire = self.call(self.gateway.model_port, '/v1/executions', {}, context)
        self.assertEqual(status, 201, wire)
        execution = json.loads(wire)['executionId']
        extra = {'x-aisp-execution-id': execution}
        status, _, wire = self.call(self.gateway.model_port, '/v1/executions/invocations',
            {'server': 'local', 'tool': 'echo', 'arguments': {}}, context, extra=extra)
        self.assertEqual(status, 201, wire)
        invocation = json.loads(wire)['invocationId']
        status, headers, values = self.mcp('initialize', {'protocolVersion': '2025-11-25',
            'capabilities': {}, 'clientInfo': {'name': 'sqlite-sampling', 'version': '1'}}, context, extra=extra)
        self.assertEqual(status, 200, values)
        session = headers['mcp-session-id']
        self.mcp('notifications/initialized', {}, context, session, extra=extra)
        self.assertEqual(self.mcp('tools/list', {}, context, session, extra=extra)[0], 200)
        status, _, values = self.mcp('tools/call', {'name': 'echo', 'arguments': {}, 'task': {'ttl': 60000}},
            context, session, extra={**extra, 'x-aisp-invocation-id': invocation})
        self.assertEqual(status, 200, values)
        task = next(v['result']['task']['taskId'] for v in values if 'result' in v)
        return context, session, task, extra

    def test_sqlite_task_sampling_uses_controlled_model_execution(self):
        context, session, task, extra = self.sampling_task()
        self.model.before_reply = lambda: time.sleep(1.1)  # Exercise periodic authorization during inference.
        status, _, values = self.mcp('tasks/result', {'taskId': task}, context, session, extra=extra)
        self.assertEqual(status, 200, values)
        self.assertTrue(any(v.get('result', {}).get('content', [{}])[0].get('text') == 'sampled' for v in values), values)
        self.assertEqual(len(self.model.requests), 1)
        self.assertEqual(len(self.tool.answers), 1)
        self.assertEqual(self.model.requests[0][2]['max_tokens'], 8)

    def test_sqlite_revocation_with_pending_sampling_never_sends_tool_answer(self):
        context, session, task, extra = self.sampling_task()
        started, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        def hold_model():
            started.set()
            if not release.wait(8):
                raise TimeoutError('sampling fixture was not released')
        self.model.before_reply = hold_model
        replies, errors = [], []
        def invoke():
            try:
                replies.append(self.mcp('tasks/result', {'taskId': task}, context, session, extra=extra))
            except BaseException as error:
                errors.append(error)
        worker = threading.Thread(target=invoke)
        worker.start()
        self.addCleanup(worker.join, 10)
        self.assertTrue(started.wait(5), 'controlled model dispatch was not reached')
        self.assertEqual(self.revoke(context)[0], 200)
        release.set()
        worker.join(8)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(self.model.requests), 1)
        self.assertEqual(self.tool.answers, [])
        self.assertFalse(any('result' in v for reply in replies for v in reply[2]), replies)

    def test_acknowledged_context_revocation_stops_pending_agent_stream(self):
        context, _ = self.begin()
        self.agent.release = threading.Event()
        self.agent.stream_started = threading.Event()
        self.addCleanup(self.agent.release.set)
        self.agent.mode = 'hold'
        message = {'kind': 'message', 'role': 'user', 'messageId': 'stream',
                   'parts': [{'kind': 'text', 'text': 'business evidence'}]}
        connection = http.client.HTTPConnection('127.0.0.1', self.agent_port, timeout=8)
        self.addCleanup(connection.close)
        connection.request('POST', '/agent', json.dumps({'jsonrpc': '2.0', 'id': 1,
            'method': 'message/stream', 'params': {'message': message}}),
            {'Authorization': 'Bearer ' + self.gateway.token(), 'Content-Type': 'application/json',
             'Accept': 'text/event-stream', 'x-aisp-context-id': context})
        response = connection.getresponse()
        self.assertEqual(response.status, 200)
        first = response.readline()
        self.assertIn(b'task-1', first)
        self.assertEqual(self.revoke(context)[0], 200)
        self.agent.release.set()
        rest = bytearray()
        try:
            while chunk := response.read(1):
                rest.extend(chunk)
        except (http.client.IncompleteRead, ConnectionError):
            pass
        self.assertNotIn(b'AFTER-REVOKE-MARKER', rest)
        self.assertNotIn(b'completed', rest)

    def test_offline_cli_import_retains_context_and_never_overwrites_destination(self):
        target = copy.deepcopy(self.system['security'])
        self.system['security'] = self.legacy_security
        self.system['rag']['lifecycle'] = self.legacy_documents
        context, retrieved = self.begin()
        revoked, _ = self.context()
        self.assertEqual(self.revoke(revoked)[0], 200)
        self.gateway.stop()
        paths = [Path(self.legacy_security['crossComponent']['storage']['path']),
                 Path(self.legacy_documents['storage']['path'])]
        before = [p.read_bytes() for p in paths]
        declaration = self.directory / 'import.json'
        declaration.write_text(json.dumps({'sourceSecurity': self.legacy_security,
            'targetSecurity': target, 'documents': self.legacy_documents}))
        command = [rag_profile.BINARY, 'import-rag-state', '--file', str(declaration)]
        imported = subprocess.run(command, capture_output=True, text=True, timeout=20)
        self.assertEqual(imported.returncode, 0, imported.stderr)
        self.assertEqual(before, [p.read_bytes() for p in paths])
        self.assertNotEqual(subprocess.run(command, capture_output=True, timeout=20).returncode, 0)
        self.system['security'] = target
        self.system['rag'].pop('lifecycle')
        self.gateway.config.write_text(json.dumps(self.config))
        self.gateway.start()
        self.assertEqual(self.generate(context, retrieved)[0], 200)
        self.assert_blocked(self.generate(revoked), 1)
        session = self.initialize(context)
        self.assertEqual(self.mcp('tools/call', {'name': 'echo', 'arguments': {'evidence': 'imported'}}, context, session)[0], 200)
        self.assertEqual(self.create(context)['status']['state'], 'completed')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=lambda p: str(Path(p).resolve()))
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    rag_profile.BINARY = args.binary
    if args.report:
        gateway_faults.ARTIFACTS = args.report.with_suffix('.gateway')
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(SqliteWorkflow))
    if args.report:
        args.report.write_text(json.dumps({'successful': result.wasSuccessful(), 'testsRun': result.testsRun,
            'failures': [str(t) for t, _ in result.failures], 'errors': [str(t) for t, _ in result.errors],
            'skipped': [str(t) for t, _ in result.skipped], 'evidence': SqliteWorkflow.evidence}, indent=2) + '\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
