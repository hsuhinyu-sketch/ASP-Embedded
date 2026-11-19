#!/usr/bin/env python3
"""Joint SQLite Context/document authority through the actual RAG -> LLM gateway."""
import argparse
import json
import os
from pathlib import Path
import sqlite3
import time
import unittest

import gateway_faults
import rag_profile
from rag_llm_profile import RagLlm


class RagSqlite(RagLlm):
    evidence = {}

    def setUp(self):
        super().setUp()
        if self.gateway.artifacts is not None:
            self.gateway.artifacts /= self.id().rsplit('.', 1)[-1]
        flow = self.system['security']['crossComponent']
        flow.pop('storage')
        flow['sqlite'] = {
            'path': str(self.directory / 'rag.sqlite'), 'namespace': flow['namespace'],
            'maxContexts': flow.get('maxContexts', 1024), 'maxDocuments': 4096,
            'maxDatabaseBytes': 1048576, 'busyTimeoutMillis': 100,
        }
        self.system['rag'].pop('lifecycle')

    def test_context_journal_failure_is_closed_before_model(self):
        context, result = self.begin()
        # Replacing the database must quarantine the live authority, including its WAL.
        database = self.directory / 'rag.sqlite'
        database.rename(database.with_suffix('.replaced'))
        database.write_bytes(b'')
        os.chmod(database, 0o600)
        self.assert_blocked(self.generate(context, result), 0)

    def test_document_authority_failure_is_closed_before_model(self):
        context, result = self.begin()
        os.chmod(self.directory / 'rag.sqlite', 0o644)
        self.assert_blocked(self.generate(context, result), 0)

    def test_retries_recheck_context_and_stop_after_acknowledged_revocation(self):
        self.config['policies'] = [{'name': {'name': 'context-retry', 'namespace': 'internal'},
            'target': {'route': {'name': f'ai-system:{self.system["name"]}:llm:request', 'namespace': 'internal'}},
            'policy': {'retry': {'attempts': 3, 'codes': [503]}}}]
        context, result = self.begin()
        self.model.before_reply = lambda: 503 if len(self.model.requests) == 1 else None
        self.assertEqual(self.generate(context, result)[0], 200)
        self.assertEqual(len(self.model.requests), 2)
        fresh, evidence = self.context()
        acknowledgements = []
        def revoke_before_retry():
            acknowledgements.append(self.revoke(fresh)[0])
            return 503
        self.model.before_reply = revoke_before_retry
        self.assert_blocked(self.generate(fresh, evidence), 3)
        self.assertEqual(acknowledgements, [200])

    def test_restart_recovers_context_and_acknowledged_revocation(self):
        live, result = self.begin()
        revoked, _ = self.context()
        self.assertEqual(self.revoke(revoked)[0], 200)
        self.gateway.stop()
        self.gateway.start()
        self.assertEqual(self.generate(live, result)[0], 200)
        self.assert_blocked(self.generate(revoked), 1)

    def test_repeated_use_keeps_fixed_state_and_does_not_create_journals(self):
        context, result = self.begin()
        latencies = []
        peak = 0
        self.model.stream_frames = 20
        for _ in range(40):
            start = time.perf_counter_ns()
            connection, response = self.generate(context, result, stream=True)
            try:
                self.assertEqual(response.status, 200)
                wire = response.read()
                self.assertEqual(wire.count(b'data: '), 20)
                self.assertIn(b'FRAME_19', wire)
            finally:
                connection.close()
            latencies.append((time.perf_counter_ns() - start) / 1e6)
            peak = max(peak, sum(path.stat().st_size for path in self.directory.glob('rag.sqlite*')))
        self.assertFalse((self.directory / 'contexts.jsonl').exists())
        self.assertFalse((self.directory / 'documents.jsonl').exists())
        with sqlite3.connect(f'file:{self.directory / "rag.sqlite"}?mode=ro', uri=True) as db:
            contexts = db.execute('SELECT count(*) FROM asp_rag_contexts').fetchone()[0]
            documents = db.execute('SELECT count(*) FROM asp_rag_documents').fetchone()[0]
        self.assertEqual((contexts, documents), (1, 1))
        self.evidence[self.id()] = {'requests': 40, 'framesPerResponse': 20, 'deliveredFrames': 800, 'contextRows': contexts, 'documentRows': documents,
            'databaseAndSidecarsPeakBytes': peak, 'httpP50Millis': sorted(latencies)[20],
            'httpP95Millis': sorted(latencies)[37], 'note': 'debug local HTTP, not fsync count or production benchmark'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=lambda p: str(Path(p).resolve()))
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    rag_profile.BINARY = args.binary
    if args.report:
        gateway_faults.ARTIFACTS = args.report.with_suffix('.gateway')
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RagSqlite))
    if args.report:
        args.report.write_text(json.dumps({'successful': result.wasSuccessful(), 'testsRun': result.testsRun,
            'failures': [str(t) for t, _ in result.failures], 'errors': [str(t) for t, _ in result.errors],
            'skipped': [str(t) for t, _ in result.skipped], 'evidence': RagSqlite.evidence}, indent=2) + '\n')
    raise SystemExit(0 if result.wasSuccessful() else 1)
