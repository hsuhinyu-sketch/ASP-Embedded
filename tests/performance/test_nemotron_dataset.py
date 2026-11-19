import unittest

from nemotron_dataset import normalize, reservoir
from pii_dataset import score


def record(text, spans, locale='us'):
    return {'uid': 'one', 'text': text, 'spans': spans, 'locale': locale,
            'domain': 'test', 'document_format': 'structured'}


class NemotronTests(unittest.TestCase):
    def test_character_spans_convert_to_utf8_and_preserve_unmatched_occurrences(self):
        row = normalize(record('甲😀 a@b.com a@b.com', str([
            {'start': 3, 'end': 10, 'text': 'a@b.com', 'label': 'email'}])))
        self.assertEqual(row['gold'], [{'start': 8, 'end': 15, 'entityType': 'EMAIL_ADDRESS'}])
        self.assertEqual(row['id'], 'us:one')
        self.assertEqual(row['sourceUid'], 'one')

    def test_bad_range_or_text_is_rejected_without_offset_repair(self):
        for start, end, text in ((-1, 2, 'a@'), (0, 100, 'a@b.com'),
                                 (0, 2, 'a@b.com'), (False, 7, 'a@b.com')):
            with self.subTest(start=start, end=end), self.assertRaises(ValueError):
                normalize(record('a@b.com', [{'start': start, 'end': end, 'text': text, 'label': 'email'}]))

    def test_source_case_and_numeric_text_representations_keep_original_offsets(self):
        row = normalize(record('Black 60', [
            {'start': 0, 'end': 5, 'text': 'black', 'label': 'race_ethnicity'},
            {'start': 6, 'end': 8, 'text': 60, 'label': 'age'}]))
        self.assertEqual(row['annotationNormalizations'], {'case-only': 1, 'numeric-text': 1})
        self.assertEqual([(s['start'], s['end']) for s in row['gold']], [(0, 5), (6, 8)])

    def test_locale_variants_do_not_collide_and_unknown_types_remain_visible(self):
        source = [{'start': 0, 'end': 5, 'text': 'Alice', 'label': 'first_name'}]
        us, intl = (normalize(record('Alice', source, locale)) for locale in ('us', 'intl'))
        self.assertNotEqual(us['id'], intl['id'])
        self.assertEqual(us['gold'][0]['entityType'], 'source:first_name')
        metrics = score([us], [{'id': us['id'], 'findings': []}], 'official-spans')
        self.assertEqual(metrics['annotationMethod'], 'official-spans')
        self.assertEqual(metrics['allAnnotatedSpans'], 1)
        self.assertEqual(metrics['supportedAnnotatedSpans'], 0)

    def test_reservoir_is_reproducible_stratified_and_without_replacement(self):
        rows = [{**record('', [], locale), 'uid': str(i)}
                for locale in ('us', 'intl') for i in range(100)]
        selected, populations = reservoir(iter(rows), 7)
        self.assertEqual(selected, reservoir(iter(rows), 7)[0])
        self.assertEqual(len(selected), 14)
        self.assertEqual(len({(r['locale'], r['uid']) for r in selected}), 14)
        self.assertEqual(populations[('us', 'structured')], 100)
        self.assertEqual(sum(r['locale'] == 'us' for r in selected), 7)
