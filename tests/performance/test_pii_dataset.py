import unittest

from gretel_dataset import counts, covered, normalize, rates, score


def record(text, entities):
    return normalize({'uid': 'one', 'domain': 'test', 'text': text, 'entities': entities})


class DatasetScoringTests(unittest.TestCase):
    def test_literal_labels_reconstruct_repeated_utf8_spans_without_duplicates(self):
        row = record('甲😀 a@b.com a@b.com', str([
            {'entity': 'a@b.com', 'types': ['email']},
            {'entity': 'a@b.com', 'types': ['email']},
            {'entity': 'absent', 'types': ['first_name']}]))
        self.assertEqual(row['gold'], [{'start': 8, 'end': 15, 'entityType': 'EMAIL_ADDRESS'},
                                       {'start': 16, 'end': 23, 'entityType': 'EMAIL_ADDRESS'}])
        self.assertEqual(row['missingAnnotations'], {'first_name': 1})

    def test_unsupported_entities_are_visible_but_not_in_supported_denominator(self):
        row = record('Alice a@b.com', [{'entity': 'Alice', 'types': ['name']},
                                       {'entity': 'a@b.com', 'types': ['email']}])
        result = score([row], [{'id': 'one', 'findings': [row['gold'][1]]}])
        self.assertEqual(result['supported']['recall'], 1)
        self.assertEqual(result['supportedSpanCoverage'], .5)
        self.assertEqual(result['allAnnotatedSpans'], 2)

    def test_partial_span_and_wrong_type_are_not_true_positives(self):
        gold = {(0, 10, 'PHONE_NUMBER')}
        for predicted in ({(0, 9, 'PHONE_NUMBER')}, {(0, 10, 'IP_ADDRESS')}):
            self.assertEqual(counts(gold, predicted), {'tp': 0, 'fp': 1, 'fn': 1})
        self.assertTrue(covered((0, 10, 'PHONE_NUMBER'), {(0, 5, 'A'), (5, 10, 'B')}))
        self.assertFalse(covered((0, 10, 'PHONE_NUMBER'), {(0, 4, 'A'), (5, 10, 'B')}))

    def test_engine_errors_remain_false_negatives_and_alignment_errors_fail(self):
        row = record('a@b.com', [{'entity': 'a@b.com', 'types': ['email']}])
        value = score([row], [{'id': 'one', 'error': 'PII detector unavailable'}])
        self.assertEqual(value['supported']['fn'], 1)
        self.assertEqual(value['exactDocuments'], 0)
        self.assertEqual(value['engineErrors'], {'PII detector unavailable': 1})
        for outputs in ([], [{'id': 'wrong', 'findings': []}]):
            with self.assertRaises(ValueError):
                score([row], outputs)

    def test_empty_classes_do_not_fabricate_perfect_metrics(self):
        self.assertEqual(rates({'tp': 0, 'fp': 0, 'fn': 0}),
                         {'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'f1': None})
