"""Metric arithmetic and labelled-corpus integrity; no detector-result expectations."""
import unittest

from cross_protocol_corpus import HOLDOUT, compare_detection, detection_metrics, load_corpus


class CorpusMetrics(unittest.TestCase):
    def test_confusion_matrix_uses_labels_and_observed_isolation(self):
        rows = [{'label': label, 'isolatedByContextGuard': isolated} for label, isolated in [
            ('attack', True), ('attack', True), ('attack', False),
            ('benign', True), ('benign', False), ('benign', False)]]
        metrics = detection_metrics(rows)
        self.assertEqual([metrics[key] for key in ['truePositives', 'falseNegatives',
            'falsePositives', 'trueNegatives']], [2, 1, 1, 2])
        self.assertAlmostEqual(metrics['precision'], 2 / 3)
        self.assertAlmostEqual(metrics['recall'], 2 / 3)
        self.assertAlmostEqual(metrics['falsePositiveRate'], 1 / 3)
        self.assertAlmostEqual(metrics['accuracy'], 4 / 6)

    def test_undefined_rates_are_not_fabricated_as_perfect_scores(self):
        empty = detection_metrics([])
        self.assertTrue(all(empty[key] is None for key in ['precision', 'recall', 'falsePositiveRate', 'accuracy']))
        missed = detection_metrics([{'label': 'attack', 'isolatedByContextGuard': False}])
        self.assertIsNone(missed['precision'])
        self.assertEqual(missed['recall'], 0)
        self.assertIsNone(missed['falsePositiveRate'])

    def test_diagnostic_corpus_has_unique_ids_and_explicit_balanced_labels(self):
        samples = load_corpus()
        self.assertEqual(len(samples), 24)
        self.assertEqual(len({sample['id'] for sample in samples}), 24)
        self.assertEqual(sum(sample['label'] == 'attack' for sample in samples), 12)
        self.assertEqual(sum(sample['label'] == 'benign' for sample in samples), 12)
        self.assertTrue(all(sample['text'] and sample['family'] for sample in samples))
        self.assertTrue(any(sample['family'] == 'quoted-security-text' for sample in samples))

    def test_holdout_families_and_text_are_separate_from_diagnostics(self):
        diagnostic, holdout = load_corpus(), load_corpus(HOLDOUT)
        self.assertEqual(len(holdout), 12)
        for field in ('id', 'text', 'family'):
            self.assertTrue({row[field] for row in diagnostic}.isdisjoint(row[field] for row in holdout))
        self.assertEqual(len({row['id'] for row in holdout}), 12)
        self.assertEqual(sum(row['label'] == 'attack' for row in holdout), 6)
        self.assertEqual(sum(row['label'] == 'benign' for row in holdout), 6)

    def test_comparison_rejects_case_regression_even_when_recall_rises(self):
        rows = [{'cohort': 'holdout', 'ruleSet': rules, 'id': str(index),
                 'label': label, 'family': 'fixture', 'isolatedByContextGuard': isolated}
                for rules, results in [('legacy', (True, False, False, True)),
                                       ('contextual', (False, True, True, False))]
                for index, (label, isolated) in enumerate(zip(('attack', 'attack', 'attack', 'benign'), results))]
        report, failures = compare_detection(rows)
        self.assertGreater(report['holdout']['contextual']['overall']['recall'],
                           report['holdout']['legacy']['overall']['recall'])
        self.assertEqual(failures, [{'type': 'PreviouslyBlockedAttackReachedModel', 'cases': [('holdout', '0')]}])
