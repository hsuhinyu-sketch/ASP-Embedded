import io
import json
import time
import unittest
from unittest.mock import patch

from pathlib import Path

from run_cloud_probe import TARGETS, CompletionError, call, completion


class Response(io.BytesIO):
    def getheader(self, name, default=None):
        return 'text/event-stream' if name == 'Content-Type' else default


def frame(value):
    return b'data: ' + json.dumps(value).encode() + b'\r\n\r\n'


def delta(value=None, finish=None):
    return {'choices': [{'index': 0, 'delta': value or {}, 'finish_reason': finish}]}


class CloudStreamTests(unittest.TestCase):
    def test_cloud_targets_keep_credentials_and_request_formats_separate(self):
        for name in ('pai', 'mimo'):
            target = TARGETS[name]
            sent = []
            class Denied(Response):
                status = 403
            class Connection:
                def request(self, method, path, body, headers):
                    sent.append((json.loads(body), headers))
                def getresponse(self):
                    return Denied(b'{}')
            with self.subTest(provider=name):
                call(Connection(), target.headers('synthetic-key'), target=target, expected=403)
                body, headers = sent[0]
                self.assertEqual(body['model'], target.model)
                backend = target.backend(Path('/private/key'))
                self.assertEqual(backend['params']['baseUrl'], 'https://' + target.host + '/v1')
                self.assertNotIn('synthetic-key', json.dumps(backend))
                if name == 'mimo':
                    self.assertEqual(headers['api-key'], 'synthetic-key')
                    self.assertNotIn('Authorization', headers)
                    self.assertEqual(body['max_completion_tokens'], 32)
                    self.assertEqual(body['thinking'], {'type': 'disabled'})
                    self.assertNotIn('max_tokens', body)
                    self.assertNotIn('apiKey', backend['params'])
                    self.assertEqual(backend['auth']['key']['location'], {'header': {'name': 'api-key'}})
                else:
                    self.assertEqual(headers['Authorization'], 'Bearer synthetic-key')
                    self.assertEqual(body['max_tokens'], 32)
                    self.assertNotIn('thinking', body)
                    self.assertEqual(backend['params']['apiKey'], {'file': '/private/key'})

    def test_audit_unavailable_status_is_not_accepted_as_an_authorization_refusal(self):
        class Unavailable(Response):
            status = 503
        class Connection:
            def request(self, *args):
                pass
            def getresponse(self):
                return Unavailable(b'{}')
        self.assertEqual(call(Connection(), {}, expected=503)['status'], 503)
        for expected in (200, 403):
            with self.subTest(expected=expected), self.assertRaises(ValueError):
                call(Connection(), {}, expected=expected)

    def test_first_content_excludes_empty_role_and_reasoning_and_keeps_usage(self):
        wire = frame(delta({'role': 'assistant'})) + frame(delta({'reasoning_content': 'reason'}))
        wire += frame(delta({'content': 'READY'})) + frame(delta(finish='stop'))
        wire += frame({'choices': [], 'usage': {'total_tokens': 9}}) + b'data: [DONE]\r\n\r\n'
        with patch('run_cloud_probe.time.monotonic', return_value=1.75):
            result = completion(Response(wire), True, 1.0)
        self.assertEqual(result['firstContentMs'], 750)
        self.assertEqual(result['usage']['total_tokens'], 9)

    def test_missing_done_or_finish_and_length_termination_fail(self):
        text = frame(delta({'content': 'READY'}))
        for wire in (text + frame(delta(finish='stop')), text + b'data: [DONE]\n\n',
                     text + frame(delta(finish='length')) + b'data: [DONE]\n\n'):
            with self.subTest(), self.assertRaises(ValueError):
                completion(Response(wire), True, time.monotonic())

    def test_error_event_and_content_after_terminal_fail(self):
        text = frame(delta({'content': 'READY'})) + frame(delta(finish='stop'))
        for wire in (frame({'error': {'message': 'upstream error'}}),
                     text + b'data: [DONE]\n\n' + frame(delta({'content': 'extra'})),
                     text + frame(delta({'content': 'extra'})) + b'data: [DONE]\n\n'):
            with self.subTest(), self.assertRaises(ValueError):
                completion(Response(wire), True, time.monotonic())

    def test_event_size_is_bounded(self):
        with self.assertRaises(ValueError):
            completion(Response(b'data: ' + b'x' * 65536), True, time.monotonic())

    def test_json_model_error_or_truncation_does_not_count_as_success(self):
        for value in ({'error': {'code': 'upstream_error'}},
                      {'choices': [{'finish_reason': 'length', 'message': {'content': 'READY'}}]}):
            with self.subTest(), self.assertRaises(ValueError):
                completion(Response(json.dumps(value).encode()), False, time.monotonic())

    def test_completion_diagnostics_distinguish_answer_mismatch_from_missing_terminal(self):
        wire = frame(delta({'content': 'READY.'})) + frame(delta(finish='stop')) + b'data: [DONE]\n\n'
        with self.assertRaises(CompletionError) as captured:
            completion(Response(wire), True, time.monotonic())
        self.assertEqual(captured.exception.state, {'pendingEvent': False, 'donePresent': True,
            'finishPresent': True, 'answerMatched': False, 'contentCharacters': 6})
        self.assertNotIn('READY', str(captured.exception))
        with self.assertRaises(CompletionError) as captured:
            completion(Response(frame(delta({'content': 'READY'}))), True, time.monotonic())
        self.assertFalse(captured.exception.state['donePresent'])
        self.assertFalse(captured.exception.state['finishPresent'])
        self.assertTrue(captured.exception.state['answerMatched'])
