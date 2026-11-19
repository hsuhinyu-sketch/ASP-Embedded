import unittest

from context_guard_semantic import comparison


class DetectorComparison(unittest.TestCase):
    def test_model_only_adds_isolation_and_reports_incremental_false_removal(self):
        rows = [
            {'label': 'attack', 'isolatedByContextGuard': True, 'score': 0.01, 'language': 'en', 'family': 'rule'},
            {'label': 'attack', 'isolatedByContextGuard': False, 'score': 0.90, 'language': 'zh', 'family': 'semantic'},
            {'label': 'benign', 'isolatedByContextGuard': False, 'score': 0.91, 'language': 'zh', 'family': 'quote'},
            {'label': 'benign', 'isolatedByContextGuard': False, 'score': 0.89, 'language': 'en', 'family': 'quote'},
        ]
        counts = comparison(rows, 0.90)
        self.assertEqual(counts['overall']['rules']['detected'], 1)
        self.assertEqual(counts['overall']['rulesPlusModel']['detected'], 2)
        self.assertEqual(counts['overall']['rulesPlusModel']['falseRemovals'], 1)
        self.assertEqual(counts['language']['zh']['rulesPlusModel'],
                         {'attacks': 1, 'benign': 1, 'detected': 1, 'falseRemovals': 1})
        self.assertEqual(counts['family']['quote']['rulesPlusModel']['falseRemovals'], 1)
