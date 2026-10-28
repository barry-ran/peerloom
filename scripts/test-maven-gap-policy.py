#!/usr/bin/env python3
"""精确 Maven 原文缺项披露策略：实际已核POM/notice fixtures，不联网。"""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('maven_gap_policy', Path(__file__).with_name('maven-gap-policy.py'))
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
FIXTURE = Path(__file__).parent / 'testdata/maven-gap-proof'


class MavenGapPolicyTests(unittest.TestCase):
    def setUp(self):
        self.report = copy.deepcopy(policy.PINS['expected_report'])

    def rejected(self):
        self.assertEqual(policy.classify(self.report), (policy.INCOMPLETE, []))
        with self.assertRaisesRegex(ValueError, 'UNAPPROVED'):
            policy.verify_bound_files(self.report, lambda name: (FIXTURE / name).read_bytes())

    def test_exact_real_report_and_preserved_original_bytes(self):
        status, gaps = policy.classify(self.report)
        self.assertEqual(status, policy.DOCUMENTED)
        self.assertEqual(len(gaps), 19)
        self.assertEqual(self.report['evidence_status'], policy.INCOMPLETE)
        policy.verify_bound_files(self.report, lambda name: (FIXTURE / name).read_bytes())

    def test_unknown_version_binary_digest_bytes_or_pom(self):
        for field, value in [('coordinate', 'other:unknown:1.0'), ('pom_sha256', '0' * 64)]:
            self.report = copy.deepcopy(policy.PINS['expected_report'])
            self.report['scopes'][0]['packages'][0][field] = value
            self.rejected()
        for field, value in [('sha256', '0' * 64), ('bytes', 1), ('name', 'other.jar')]:
            self.report = copy.deepcopy(policy.PINS['expected_report'])
            self.report['scopes'][0]['packages'][0]['artifacts'][0][field] = value
            self.rejected()

    def test_missing_or_new_scope_package_edge_and_root_issue(self):
        for mutate in [
            lambda r: r['scopes'].pop(),
            lambda r: r['scopes'][0]['packages'].pop(),
            lambda r: r['scopes'][0]['packages'].append(copy.deepcopy(r['scopes'][0]['packages'][0])),
            lambda r: r['scopes'][0]['edges'].pop(),
            lambda r: r.update(issues=['new-root-issue']),
        ]:
            self.report = copy.deepcopy(policy.PINS['expected_report'])
            mutate(self.report)
            self.rejected()

    def test_original_issues_status_declaration_binding_cannot_be_erased(self):
        for field in ['issues', 'declared_licenses', 'pom_binary_binding', 'pom_coordinate']:
            self.report = copy.deepcopy(policy.PINS['expected_report'])
            self.report['scopes'][0]['packages'][0].pop(field)
            self.rejected()
        self.report = copy.deepcopy(policy.PINS['expected_report'])
        self.report['evidence_status'] = policy.COMPLETE
        self.rejected()

    def test_available_notice_cannot_be_deleted_from_report(self):
        for scope in self.report['scopes']:
            for item in scope['packages']:
                if item['evidence']:
                    item['evidence'] = []
        self.rejected()

    def test_missing_or_modified_actual_pom_and_notice_rejected(self):
        for prefix in ['poms/', 'licenses/']:
            def missing(name):
                if name.startswith(prefix):
                    raise FileNotFoundError(name)
                return (FIXTURE / name).read_bytes()
            with self.assertRaises(FileNotFoundError):
                policy.verify_bound_files(self.report, missing)
            def altered(name):
                data = (FIXTURE / name).read_bytes()
                return data + b' ' if name.startswith(prefix) else data
            with self.assertRaisesRegex(ValueError, 'BYTES_MISMATCH'):
                policy.verify_bound_files(self.report, altered)

    def test_gap_result_is_owned_and_not_legal_approval(self):
        _, gaps = policy.classify(self.report)
        self.assertTrue(all('legal approval' in g['scope'] for g in gaps))
        gaps.clear()
        self.assertEqual(len(policy.classify(self.report)[1]), 19)


if __name__ == '__main__':
    unittest.main()
