#!/usr/bin/env python3
"""RAG -> MCP Tool -> model -> A2A Task/Artifact through the existing Gateway APIs."""
import argparse
import collections
import concurrent.futures
import copy
import http.client
import http.server
import io
import json
from pathlib import Path
import socket
import ssl
import subprocess
import threading
import unittest

import a2a_profile
import gateway_faults
import rag_profile
from rag_llm_profile import RagLlmFixture


class Tool(gateway_faults.Upstream):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers['Content-Length']))
        request = json.loads(raw)
        with self.server.lock:
            self.server.requests.append((dict(self.headers), copy.deepcopy(request)))
        if request.get('method') == 'tools/call':
            name = request['params']['name']
            with self.server.lock:
                self.server.effects[name] += 1
            self.reply(200, {'jsonrpc': '2.0', 'id': request['id'], 'result': {
                'content': [{'type': 'text', 'text': 'Tool evidence: ' + request['params']['arguments']['evidence']}]}})
        else:
            original = self.rfile
            self.rfile = io.BytesIO(raw)
            try:
                super().do_POST()
            finally:
                self.rfile = original


class Agent(a2a_profile.Agent):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers['Content-Length']))
        self.server.requests.append(json.loads(raw))
        original = self.rfile
        self.rfile = io.BytesIO(raw)
        try:
            super().do_POST()
        finally:
            self.rfile = original

    def snapshot(self, task):
        if task not in self.server.inputs:
            message = next(r for r in reversed(self.server.requests) if r['method'].startswith('message/'))
            self.server.inputs[task] = message['params']['message']['parts'][0]['text']
        # Held streams begin with a nonterminal snapshot so revocation/recovery can be observed.
        self.server.tasks[task] = 'working' if self.server.mode == 'hold' else 'completed'
        result = super().snapshot(task)
        result['artifacts'][0]['parts'][0]['text'] = 'Agent artifact: ' + self.server.inputs[task]
        return result


class WorkflowFixture(RagLlmFixture):
    evidence = {}

    def serve(self, handler):
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
        server.daemon_threads = True
        server.lock = threading.Lock()
        server.requests = []
        server.calls = collections.Counter()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def close():
            server.shutdown()
            server.server_close()
            thread.join(5)
        self.addCleanup(close)
        return server

    def reserve(self):
        reservation = self.gateway.role_ports.reservations.enter_context(socket.socket())
        reservation.bind(('127.0.0.1', 0))
        return reservation.getsockname()[1]

    def setUp(self):
        super().setUp()
        self.tool = self.serve(Tool)
        self.tool.effects = collections.Counter()
        self.agent = self.serve(Agent)
        self.agent.next_task = 0
        self.agent.tasks = {}
        self.agent.inputs = {}
        self.agent.mode = ''
        self.mcp_port, self.agent_port = self.reserve(), self.reserve()
        self.gateway.role_ports.ports.update(tool=self.mcp_port, agent=self.agent_port)
        self.gateway.listener_ports += (self.mcp_port, self.agent_port)
        security = self.system['security']
        security['mcpSessions'] = {'maxSessions': 4}
        security['a2aObjects'] = {'streamIdleSeconds': 3, 'reauthorizeSeconds': 1, 'maxStreamSeconds': 15}
        security['policies'] += [self.allow(kind) for kind in ('mcpSessionOperation', 'toolList', 'agentInvoke', 'agentTaskOperation')]
        security['policies'] += [dict(self.allow('toolInvoke'), resourceId='echo'),
                                  dict(self.allow('mcpOperation'), resourceType='mcpServer', resourceId='local')]
        self.agent_target = f'127.0.0.1:{self.agent.server_port}'
        artifact = json.dumps([self.agent_target, '/agent', 'task-1', 'visible'], separators=(',', ':'))
        security['policies'].append(dict(self.allow('agentArtifactRead'), resourceId=artifact))
        for policy in security['crossComponent']['destinations']:
            policy.update(toolDestinations=['local/echo'], mcpDestinations=['local'], agentDestinations=[self.agent_target])
        auth = self.system['rag']['authentication']
        self.system['mcp'] = {'port': self.mcp_port, 'statefulMode': 'stateful',
                              'policies': {'jwtAuth': copy.deepcopy(auth)},
                              'targets': [{'name': 'local', 'mcp': {'host': f'http://127.0.0.1:{self.tool.server_port}/mcp'}}]}
        self.system['a2a'] = {'port': self.agent_port, 'backend': {'host': self.agent_target}}
        self.config['policies'] = [{'name': {'name': 'business-a2a-jwt', 'namespace': 'internal'},
            'target': {'route': {'name': 'ai-system:knowledge-poc:a2a:request', 'namespace': 'internal'}},
            'policy': {'jwtAuth': copy.deepcopy(auth)}}]

    def mcp(self, method, params, context, session=None, token=True, extra=None):
        headers = {'Accept': 'application/json, text/event-stream', 'MCP-Protocol-Version': '2025-11-25'}
        if session:
            headers['Mcp-Session-Id'] = session
        headers.update(extra or {})
        rpc = {'jsonrpc': '2.0', 'method': method, 'params': params}
        if not method.startswith('notifications/'):
            rpc['id'] = 1
        connection, response = self.call(self.mcp_port, '/mcp', rpc, context, token, headers, stream=True)
        try:
            status, response_headers = response.status, dict(response.getheaders())
            try:
                wire = response.read()
            except http.client.IncompleteRead as error:
                wire = error.partial
        finally:
            connection.close()
        response_headers = {k.lower(): v for k, v in response_headers.items()}
        if 'text/event-stream' in response_headers.get('content-type', ''):
            values = [json.loads(line[5:]) for line in wire.decode().splitlines() if line.startswith('data:')]
        else:
            values = [json.loads(wire)] if wire.lstrip().startswith(b'{') else []
        return status, {k.lower(): v for k, v in response_headers.items()}, values

    def initialize(self, context):
        status, headers, values = self.mcp('initialize', {'protocolVersion': '2025-11-25', 'capabilities': {},
            'clientInfo': {'name': 'business-poc', 'version': '1'}}, context)
        self.assertEqual(status, 200, values)
        self.assertTrue(any('result' in v for v in values), values)
        if self.system['security']['crossComponent'].get('restrictUntrustedPayloads'):
            capabilities = next(v['result']['capabilities'] for v in values if 'result' in v)
            self.assertTrue({'tools', 'tasks', 'resources', 'prompts'}.intersection(capabilities) <= {'tools'})
        session = headers['mcp-session-id']
        self.assertIn(self.mcp('notifications/initialized', {}, context, session)[0], (200, 202, 204))
        return session

    def agent_rpc(self, method, params, context, token=True):
        return self.call(self.agent_port, '/agent', {'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params},
                         context, token)

    def create(self, context, answer='business evidence'):
        message = {'kind': 'message', 'role': 'user', 'messageId': 'business', 'parts': [{'kind': 'text', 'text': answer}]}
        status, _, wire = self.agent_rpc('message/send', {'message': message}, context)
        self.assertEqual(status, 200, wire)
        return json.loads(wire)['result']

    def assert_mcp_denied(self, response, effects):
        status, _, values = response
        self.assertTrue(status in (400, 401, 403) or any('error' in value for value in values), response)
        self.assertEqual(self.tool.effects, effects)


class Workflow(WorkflowFixture):
    evidence = {}

    def test_retrieval_tool_model_agent_artifact_business_chain(self):
        context, retrieved = self.begin()
        session = self.initialize(context)
        status, _, values = self.mcp('tools/list', {}, context, session)
        self.assertEqual(status, 200, values)
        names = [t['name'] for v in values if 'result' in v for t in v['result']['tools']]
        self.assertIn('echo', names)
        self.assertNotIn('forbidden', names)
        text = '\n'.join(c['content'] for c in retrieved['chunks'])
        status, _, values = self.mcp('tools/call', {'name': 'echo', 'arguments': {'evidence': text}}, context, session)
        self.assertEqual(status, 200, values)
        result = next(v['result'] for v in values if 'result' in v)
        tool_text = result['content'][0]['text']
        self.assertEqual(tool_text, 'Tool evidence: ' + text)
        model_input = {'chunks': [{'content': tool_text}]}
        status, _, wire = self.generate(context, model_input)
        self.assertEqual(status, 200, wire)
        answer = json.loads(wire)['choices'][0]['message']['content']
        self.assertEqual(self.model.requests[0][2]['messages'][-1]['content'], tool_text)
        task = self.create(context, answer)
        self.assertEqual(task['status']['state'], 'completed')
        self.assertEqual([a['artifactId'] for a in task['artifacts']], ['visible'])
        self.assertEqual(task['artifacts'][0]['parts'][0]['text'], 'Agent artifact: ' + answer)
        status, _, wire = self.agent_rpc('tasks/get', {'id': task['id']}, context)
        self.assertEqual(status, 200, wire)
        self.assertIn(answer, json.loads(wire)['result']['artifacts'][0]['parts'][0]['text'])
        self.evidence[self.id()] = {'toolEffects': dict(self.tool.effects), 'modelCalls': len(self.model.requests),
            'agentCalls': dict(self.agent.calls), 'allProtocolListenersUsed': True, 'visibleArtifactOnly': True}

    def test_foreign_context_owner_cannot_use_tool_session_or_agent_task(self):
        context, _ = self.begin()
        session = self.initialize(context)
        task = self.create(context)
        effects, calls = self.tool.effects.copy(), self.agent.calls.copy()
        for token in (self.gateway.token(user='bob'), self.gateway.token(tenant='tenant-b')):
            self.assert_mcp_denied(self.mcp('tools/call', {'name': 'echo', 'arguments': {'evidence': 'secret'}}, context, session, token), effects)
            self.assertIn(self.agent_rpc('tasks/get', {'id': task['id']}, context, token)[0], (400, 401, 403))
        self.assertEqual(self.agent.calls, calls)

    def test_document_revocation_blocks_tool_model_and_agent_continuations(self):
        context, retrieved = self.begin()
        session = self.initialize(context)
        task = self.create(context)
        effects, calls = self.tool.effects.copy(), self.agent.calls.copy()
        self.document({'type': 'revoke'}, self.document()['revision'])
        self.assert_mcp_denied(self.mcp('tools/call', {'name': 'echo', 'arguments': {'evidence': 'secret'}}, context, session), effects)
        self.assert_blocked(self.generate(context, retrieved), 0)
        self.assertIn(self.agent_rpc('tasks/get', {'id': task['id']}, context)[0], (400, 403))
        self.assertEqual(self.agent.calls, calls)

    def test_fresh_context_cannot_replace_task_or_session_lineage(self):
        context, _ = self.begin()
        session = self.initialize(context)
        task = self.create(context)
        self.document({'type': 'revoke'}, self.document()['revision'])
        fresh, empty = self.context()
        self.assertNotEqual(fresh, context)
        self.assertEqual(empty['chunks'], [])
        effects, calls = self.tool.effects.copy(), self.agent.calls.copy()
        self.assert_mcp_denied(self.mcp('tools/call', {'name': 'echo', 'arguments': {'evidence': 'secret'}}, fresh, session), effects)
        self.assertIn(self.agent_rpc('tasks/get', {'id': task['id']}, fresh)[0], (400, 403))
        self.assertEqual(self.agent.calls, calls)

    def test_forbidden_tool_never_has_side_effects(self):
        context, _ = self.begin()
        session = self.initialize(context)
        self.assert_mcp_denied(self.mcp('tools/call', {'name': 'forbidden', 'arguments': {'evidence': 'secret'}}, context, session), collections.Counter())

    def test_agent_actual_exit_is_separate_from_model_exit(self):
        self.system['security']['crossComponent']['destinations'][-1]['agentDestinations'] = []
        context, retrieved = self.begin()
        self.assertEqual(self.generate(context, retrieved)[0], 200)
        message = {'kind': 'message', 'role': 'user', 'messageId': 'business', 'parts': [{'kind': 'text', 'text': 'secret'}]}
        self.assertIn(self.agent_rpc('message/send', {'message': message}, context)[0], (400, 403))
        self.assertFalse(self.agent.calls)


class RestrictedTools(WorkflowFixture):
    evidence = {}

    def setUp(self):
        super().setUp()
        self.system.pop('a2a')
        self.config.pop('policies')
        self.gateway.listener_ports = tuple(port for port in self.gateway.listener_ports
                                            if port != self.agent_port)
        self.system['rag']['ingestion'] = {'defaultClassification': 'public'}
        security = self.system['security']
        security.pop('a2aObjects')
        backend = f'127.0.0.1:{self.backend.server_port}'
        security['dependencyEgress'] = {
            'requireTls': False, 'destinations': {'embedding': [backend], 'qdrant': [backend]},
        }
        flow = security['crossComponent']
        flow['restrictUntrustedPayloads'] = True
        for policy in flow['destinations']:
            policy.pop('agentDestinations')
        self.restricted = flow['destinations'][-1]

    def invoke(self, context, session, token=True, extra=None):
        return self.mcp('tools/call', {'name': 'echo', 'arguments': {'evidence': 'sample record'}},
                        context, session, token, extra)

    def test_allowed_tool_receives_body_without_client_transport_headers(self):
        context, result = self.begin()
        self.assertEqual(result['classification'], 'public')
        session = self.initialize(context)
        status, _, values = self.invoke(context, session, extra={'X-Client-Note': 'private sample'})
        self.assertEqual(status, 200, values)
        self.assertEqual(values[0]['result']['content'][0]['text'], 'Tool evidence: sample record')
        calls = [(h, req) for h, req in self.tool.requests if req.get('method') == 'tools/call']
        self.assertEqual(len(calls), 1)
        headers, forwarded = calls[0]
        names = {name.lower() for name in headers}
        self.assertTrue(names.isdisjoint({'authorization', 'x-client-note', 'x-aisp-context-id'}))
        self.assertEqual(forwarded['params']['arguments'], {'evidence': 'sample record'})

    def test_public_context_cannot_use_tool_missing_from_restricted_policy(self):
        self.restricted['toolDestinations'] = []
        context, result = self.begin()
        self.assertEqual(result['classification'], 'public')
        session = self.initialize(context)
        before = len(self.tool.requests)
        self.assert_mcp_denied(self.invoke(context, session), collections.Counter())
        self.assertEqual(len(self.tool.requests), before)

    def test_body_paths_outside_tool_contract_do_not_dispatch(self):
        context, _ = self.begin()
        session = self.initialize(context)
        before = len(self.tool.requests)
        for method, params in [('resources/read', {'uri': 'file:///sample'}),
                               ('prompts/get', {'name': 'sample'}), ('tasks/result', {'taskId': 'sample'})]:
            with self.subTest(method=method):
                self.assert_mcp_denied(self.mcp(method, params, context, session), collections.Counter())
        self.assertEqual(len(self.tool.requests), before)

    def test_foreign_revoked_and_previous_generation_do_not_dispatch(self):
        context, _ = self.begin()
        session = self.initialize(context)
        before = len(self.tool.requests)
        self.assert_mcp_denied(self.invoke(context, session, self.gateway.token(tenant='other')),
                               collections.Counter())
        self.assertEqual(self.revoke(context)[0], 200)
        self.assert_mcp_denied(self.invoke(context, session), collections.Counter())
        live, _ = self.context()
        live_session = self.initialize(live)
        before_reload = len(self.tool.requests)
        self.restricted['toolDestinations'] = []
        self.reload()
        self.assert_mcp_denied(self.invoke(live, live_session), collections.Counter())
        self.assertEqual(len(self.tool.requests), before_reload)
        self.assertTrue(all(req.get('method') != 'tools/call' for _, req in self.tool.requests[before:]))

    def test_required_tool_audit_failure_does_not_dispatch(self):
        audit = self.directory / 'audit'
        audit.mkdir(mode=0o700)
        self.config['config']['securityAudit'] = {'directory': str(audit)}
        self.system['security']['requiredAudit'] = {'actionTypes': ['toolInvoke']}
        context, _ = self.begin()
        session = self.initialize(context)
        self.assertEqual(self.invoke(context, session)[0], 200)
        self.assertTrue(list(audit.glob('segment-*.jsonl')))
        before = len(self.tool.requests)
        audit.rename(audit.with_suffix('.unavailable'))
        denied = self.invoke(context, session)
        self.assertTrue(denied[0] in (400, 401, 403, 500, 503) or any('error' in v for v in denied[2]), denied)
        self.assertEqual(len(self.tool.requests), before)
        self.assertEqual(self.tool.effects, {'echo': 1})

    def test_strict_tool_configuration_rejects_unreviewed_paths(self):
        def validate(config):
            self.gateway.config.write_text(json.dumps(config))
            return subprocess.run([self.gateway.binary, '--file', str(self.gateway.config), '--validate-only'],
                                  capture_output=True, text=True, timeout=10)

        accepted = validate(self.config)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        for feature in ('retry', 'another target', 'legacy transport'):
            with self.subTest(feature=feature):
                candidate = copy.deepcopy(self.config)
                mcp = candidate['aiSystems'][0]['mcp']
                if feature == 'retry':
                    mcp['policies']['retry'] = {'attempts': 2, 'codes': [503]}
                elif feature == 'another target':
                    mcp['targets'].append(dict(mcp['targets'][0], name='second'))
                else:
                    mcp['targets'][0]['sse'] = mcp['targets'][0].pop('mcp')
                rejected = validate(candidate)
                self.assertNotEqual(rejected.returncode, 0, rejected.stdout)
                self.assertIn('restrictUntrustedPayloads', rejected.stderr)
        self.assertFalse(self.tool.requests)

    def test_capability_consumption_and_revocation_while_waiting_for_approval(self):
        from mcp_remote_security import Authority, ProtectedTool
        from sampling_profile import tls_identity

        certificate, key = tls_identity(self.directory)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(certificate, key)

        class TlsAuthority(Authority):
            def setup(self):
                self.request = tls.wrap_socket(self.request, server_side=True)
                self.connection = self.request
                super().setup()

        authority = self.serve(TlsAuthority)
        authority.calls, authority.grants = [], {}
        authority.approved, authority.issue_error, authority.bad_binding = True, False, False
        authority.approval_ttl, authority.approval_binding, authority.hold = 10, 'respect', None
        authority.entered, authority.release, authority.finished = (threading.Event() for _ in range(3))
        tool = self.serve(ProtectedTool)
        tool.effects, tool.routing, tool.consumed = collections.Counter(), [], []
        tool.authority, tool.require_capability = authority, True
        self.system['mcp']['targets'][0]['mcp']['host'] = f'http://127.0.0.1:{tool.server_port}/mcp'
        security = self.system['security']
        endpoint = f'127.0.0.1:{authority.server_port}'
        security['dependencyEgress']['destinations'].update(approval=[endpoint], capabilityBroker=[endpoint])
        security['requiredToolApprovals'] = [{'toolName': 'echo'}]
        security['approval'] = {'endpoint': f'https://{endpoint}/approval', 'rootCaPemFile': str(certificate)}
        security['capabilityBroker'] = {'issueEndpoint': f'https://{endpoint}/issue', 'rootCaPemFile': str(certificate)}
        context, _ = self.begin()
        session = self.initialize(context)
        for _ in range(2):
            status, _, values = self.invoke(context, session)
            self.assertEqual(status, 200, values)
            self.assertTrue(any('result' in value for value in values), values)
        self.assertEqual(tool.effects, {'echo': 2})
        with authority.lock:
            self.assertEqual(len({token for token, _, _ in tool.consumed}), 2)
            self.assertTrue(all(token not in authority.grants for token, _, _ in tool.consumed))
        authority.hold = '/approval'
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(self.invoke, context, session)
            try:
                self.assertTrue(authority.entered.wait(5), 'tool approval was not reached')
                self.assertEqual(self.revoke(context)[0], 200)
            finally:
                authority.release.set()
            self.assert_mcp_denied(pending.result(timeout=10), collections.Counter())
        self.assertEqual(tool.effects, {'echo': 2})
        self.assertEqual(len(tool.consumed), 2)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=lambda p: str(Path(p).resolve()))
    parser.add_argument('--report', type=Path)
    parser.add_argument('--restricted-tools', action='store_true')
    args = parser.parse_args()
    rag_profile.BINARY = args.binary
    if args.report:
        gateway_faults.ARTIFACTS = args.report.with_suffix('.gateway')
    test_class = RestrictedTools if args.restricted_tools else Workflow
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(test_class))
    if args.report:
        args.report.write_text(json.dumps({'successful': result.wasSuccessful(), 'testsRun': result.testsRun,
            'failures': [str(t) for t, _ in result.failures], 'errors': [str(t) for t, _ in result.errors],
            'skipped': [str(t) for t, _ in result.skipped], 'evidence': test_class.evidence}, indent=2) + '\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
