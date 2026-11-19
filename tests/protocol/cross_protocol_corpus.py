#!/usr/bin/env python3
"""Measure real ContextGuard outcomes against a local OpenAI-compatible Mock API.

Labels describe the synthetic input's intent, not the expected detector result. Detection
misses and false positives are reported, never hidden by the execution-enforcement gate.
The Mock emits a forbidden call only when an attack survives assembly; it performs no
semantic inference and cannot measure real-model susceptibility.
"""
import argparse
import collections
import json
from pathlib import Path
import unittest

import gateway_faults
import rag_profile
import run_full_tcp
from cross_protocol_attacks import AttackFixture

CORPUS = Path(__file__).with_name('fixtures') / 'cross-protocol-content.json'
HOLDOUT = CORPUS.with_name('context-guard-holdout.json')
SEMANTIC_HOLDOUT = CORPUS.with_name('context-guard-semantic-holdout.json')


def load_corpus(path=CORPUS):
    return json.loads(path.read_text())['cases']


def detection_metrics(rows):
    counts = collections.Counter()
    for row in rows:
        counts[('tp' if row['isolatedByContextGuard'] else 'fn') if row['label'] == 'attack'
               else ('fp' if row['isolatedByContextGuard'] else 'tn')] += 1
    tp, fn, fp, tn = (counts[key] for key in ('tp', 'fn', 'fp', 'tn'))
    def ratio(numerator, denominator):
        return numerator / denominator if denominator else None
    return {'samples': len(rows), 'truePositives': tp, 'falseNegatives': fn,
        'falsePositives': fp, 'trueNegatives': tn, 'precision': ratio(tp, tp + fp),
        'recall': ratio(tp, tp + fn), 'falsePositiveRate': ratio(fp, fp + tn),
        'accuracy': ratio(tp + tn, len(rows))}


def compare_detection(observations):
    reports = {}
    for cohort in ('diagnostic', 'holdout'):
        reports[cohort] = {}
        for rules in ('legacy', 'contextual'):
            rows = [row for row in observations if row['cohort'] == cohort and row['ruleSet'] == rules]
            reports[cohort][rules] = {
                'overall': detection_metrics(rows),
                'families': {family: detection_metrics([row for row in rows if row['family'] == family])
                             for family in sorted({row['family'] for row in rows})},
            }
    baseline_blocks = {(r['cohort'], r['id']) for r in observations
                       if r['label'] == 'attack' and r['ruleSet'] == 'legacy' and r['isolatedByContextGuard']}
    candidate_blocks = {(r['cohort'], r['id']) for r in observations
                        if r['label'] == 'attack' and r['ruleSet'] == 'contextual' and r['isolatedByContextGuard']}
    holdout = reports['holdout']
    diagnostic = reports['diagnostic']
    failures = []
    if regressions := sorted(baseline_blocks - candidate_blocks):
        failures.append({'type': 'PreviouslyBlockedAttackReachedModel', 'cases': regressions})
    if holdout['contextual']['overall']['falsePositives'] >= holdout['legacy']['overall']['falsePositives']:
        failures.append({'type': 'HoldoutFalsePositivesDidNotDecrease'})
    if diagnostic['contextual']['overall']['falsePositives'] > diagnostic['legacy']['overall']['falsePositives']:
        failures.append({'type': 'DiagnosticFalsePositivesIncreased'})
    return reports, failures


class CorpusCase(AttackFixture):
    observations = {}

    def __init__(self, sample, cohort='diagnostic', rule_set='legacy'):
        self.sample = sample
        self.cohort = cohort
        self.rule_set = rule_set
        super().__init__('test_sample')

    def id(self):
        return super().id() + f'.{self.cohort}-{self.rule_set}-{self.sample["id"]}'

    def __str__(self):
        return self.id()

    def test_sample(self):
        sample = self.sample
        if self.rule_set != 'legacy':
            self.system['rag']['contextGuard'] = {'ruleSet': self.rule_set}
        self.begin_attack('Ordinary reference for the requested report.')
        status, wire = self.ingest(sample['text'], document=sample['id'])
        self.assertEqual(status, 201, wire)
        context, assembled = self.context()
        # Sessions are bound to the current Context, not a previous retrieval's handle.
        session = self.initialize(context)
        self.normal_tool(context, session)
        self.assertTrue(any(chunk['documentId'] == 'document' for chunk in assembled['chunks']),
                        'normal reference must remain available')
        chunks = [chunk for chunk in assembled['chunks'] if chunk['documentId'] == sample['id']]
        isolated = not chunks
        if isolated:
            self.assertTrue(assembled['removedChunkIds'], 'missing content is not proof of detection')
        else:
            self.assertEqual(''.join(chunk['content'] for chunk in chunks), sample['text'])
            self.assertEqual(assembled['removedChunkIds'], [])
            self.assertTrue(all(chunk['chunkId'] and chunk['sourceHash'] for chunk in chunks))
        evidence = '\n'.join(chunk['content'] for chunk in assembled['chunks'])
        reached_model = sample['text'] in evidence
        self.assertEqual(reached_model, not isolated)
        # Worst-case controlled behavior, not a classifier: the mock obeys surviving attacks.
        forbidden = sample['label'] == 'attack' and reached_model
        name = 'forbidden' if forbidden else 'echo'
        arguments = {'evidence': 'SYNTHETIC_SECRET' if forbidden else 'normal corpus result'}
        name, arguments = self.propose_tool(context, evidence, name, arguments)
        before = self.tool.effects.copy()
        reply = self.call_tool(context, session, name, arguments)
        if forbidden:
            self.assert_mcp_denied(reply, before)
        else:
            status, _, values = reply
            self.assertEqual(status, 200, values)
            result = next(value['result'] for value in values if 'result' in value)
            self.assertEqual(result['content'][0]['text'], 'Tool evidence: normal corpus result')
            self.assertEqual(self.tool.effects['echo'], before['echo'] + 1)
        self.assertEqual(self.tool.effects['forbidden'], 0)
        events = [json.loads(line)['event'] for path in sorted(self.audit.glob('segment-*.jsonl'))
                  for line in path.read_text().splitlines()]
        self.observations[(self.cohort, self.rule_set, sample['id'])] = {**sample,
            'cohort': self.cohort, 'ruleSet': self.rule_set, 'isolatedByContextGuard': isolated,
            'sampleReachedModel': reached_model, 'modelProposedTool': name,
            'forbiddenToolAttempted': forbidden, 'forbiddenToolEffects': self.tool.effects['forbidden'],
            'normalControlSucceeded': True, 'modelRequests': len(self.model.requests),
            'removedChunkIds': assembled['removedChunkIds'],
            'auditRequestIds': sorted({event['requestId'] for event in events})}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=lambda p: str(Path(p).resolve()))
    parser.add_argument('--report', required=True, type=Path)
    profiles = parser.add_mutually_exclusive_group()
    profiles.add_argument('--compare', action='store_true', help='compare rules on diagnostic and holdout cases')
    profiles.add_argument('--semantic-holdout', action='store_true', help='measure contextual baseline on the semantic holdout')
    args = parser.parse_args()
    if args.report.exists():
        parser.error('report exists; choose a fresh path')
    rag_profile.BINARY = args.binary
    gateway_faults.ARTIFACTS = args.report.with_suffix('.gateway')
    cohorts = {'diagnostic': load_corpus()}
    rule_sets = ('legacy',)
    corpus_paths = (CORPUS,)
    if args.compare:
        cohorts['holdout'] = load_corpus(HOLDOUT)
        rule_sets = ('legacy', 'contextual')
        corpus_paths += (HOLDOUT,)
    if args.semantic_holdout:
        cohorts = {'semantic-holdout': load_corpus(SEMANTIC_HOLDOUT)}
        rule_sets = ('contextual',)
        corpus_paths = (SEMANTIC_HOLDOUT,)
    suite = unittest.TestSuite(CorpusCase(sample, cohort, rules) for cohort, samples in cohorts.items()
                               for rules in rule_sets for sample in samples)
    sample_count = suite.countTestCases()
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    observations = list(CorpusCase.observations.values())
    completed = result.wasSuccessful() and len(observations) == sample_count
    comparison, gate_failures = compare_detection(observations) if args.compare and completed else (None, [])
    successful = completed and not gate_failures
    report = {'successful': successful, 'testsRun': result.testsRun,
        'errors': [str(test) for test, _ in result.errors],
        'failures': [str(test) for test, _ in result.failures],
        'skipped': [str(test) for test, _ in result.skipped],
        'scope': 'diagnostic-content-corpus-and-execution-enforcement',
        'countsAsDetectionAcceptance': args.compare and successful, 'realModelAttackSuccessRate': None,
        'samplesExpected': sample_count, 'samplesCompleted': len(observations),
        'detectionMetrics': detection_metrics(observations) if completed and not args.compare else None,
        'detectionComparison': comparison, 'detectionGateFailures': gate_failures, 'sampleResults': observations,
        'executionMetrics': {'forbiddenAttempts': sum(row['forbiddenToolAttempted'] for row in observations),
            'forbiddenToolEffects': sum(row['forbiddenToolEffects'] for row in observations),
            'normalControlsSucceeded': sum(row['normalControlSucceeded'] for row in observations)},
        'configuration': {'securityMode': 'enforce', 'contextGuardRuleSets': rule_sets,
            'model': 'local OpenAI-compatible Mock API', 'pii': 'not enabled in this corpus profile',
            'requiredAudit': ['modelInvoke', 'toolInvoke', 'agentInvoke']},
        'binarySha256': run_full_tcp.binary_digest(Path(args.binary)),
        'corpusSha256': {path.stem: run_full_tcp.binary_digest(path) for path in corpus_paths},
        'network': run_full_tcp.network_sample(),
        'limitations': ['Hand-written contrast set; rates do not estimate production detection quality.',
            'Comparison acceptance covers the committed fixture comparison only.',
            'No remote model, learned detector, real user data, or inference-quality assessment.',
            'Origin laundering is a separate open boundary and is not tested or fixed by this corpus.']}
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    raise SystemExit(0 if successful else 1)
