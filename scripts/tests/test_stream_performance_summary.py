#!/usr/bin/env python3
"""性能统计完整性回归；不运行网络负载。"""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    'summary', Path(__file__).parents[1] / 'summarize-stream-performance.py')
SUMMARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUMMARY)


class SummaryTests(unittest.TestCase):
    def rows(self):
        result = []
        for repeat in range(5):
            # 候选先出现，不能被误当成基线。
            for variant, value in [('candidate', 90.0), ('baseline', 100.0)]:
                result.append(dict(kind='measurement', valid=True, exit_code=0,
                                   connections=1, size=64, repeat=repeat, variant=variant,
                                   **{metric: value for metric in SUMMARY.METRICS['stream']}))
        return result

    def run_summary(self, rows):
        return SUMMARY.summarize(rows, 'baseline', 'candidate', 5, 'stream')

    def test_explicit_direction_and_interval(self):
        results = self.run_summary(self.rows())
        for metric in results[0]['metrics'].values():
            self.assertAlmostEqual(metric['paired_percent_change'], -10.0)
            for bound in metric['bootstrap95']:
                self.assertAlmostEqual(bound, -10.0)

    def test_duplicate_rejected(self):
        rows = self.rows()
        with self.assertRaisesRegex(ValueError, '重复'):
            self.run_summary(rows + [rows[0]])

    def test_missing_pair_rejected(self):
        with self.assertRaisesRegex(ValueError, '不完整'):
            self.run_summary(self.rows()[:-1])

    def test_invalid_run_rejected(self):
        rows = self.rows()
        rows[0]['valid'] = False
        with self.assertRaisesRegex(ValueError, '无效'):
            self.run_summary(rows)

    def test_wrong_variant_rejected(self):
        rows = self.rows()
        rows[0]['variant'] = 'unexpected'
        with self.assertRaisesRegex(ValueError, '未指定版本'):
            self.run_summary(rows)

    def test_non_finite_rejected(self):
        rows = self.rows()
        rows[0]['cpu_ns_per_byte'] = float('nan')
        with self.assertRaisesRegex(ValueError, '非有限'):
            self.run_summary(rows)

    def test_empty_rejected(self):
        with self.assertRaisesRegex(ValueError, '没有测量'):
            self.run_summary([])

    def test_unexpected_kind_rejected(self):
        rows = self.rows()
        rows[0]['kind'] = 'profile'
        with self.assertRaisesRegex(ValueError, '记录类型'):
            self.run_summary(rows)

    def test_worker_profile_rejected(self):
        rows = self.rows()
        for row in rows:
            row.update(kind='sdk_worker_backpressure', bytes=row.pop('size'),
                       poll_counting=True)
        with self.assertRaisesRegex(ValueError, '插桩'):
            SUMMARY.summarize(rows, 'baseline', 'candidate', 5, 'worker')


if __name__ == '__main__':
    unittest.main()
