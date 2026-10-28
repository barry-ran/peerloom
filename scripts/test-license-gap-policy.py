#!/usr/bin/env python3
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('gaps', Path(__file__).with_name('license-gap-policy.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

def fixture():
    packages = []
    for (name, version), (checksum, provenance) in m.KNOWN.items():
        record = {'ecosystem': 'cargo', 'name': name, 'version': version, 'purl': f'pkg:cargo/{name}@{version}',
                  'archive_sha256': checksum, 'declared_license': 'MIT OR Apache-2.0',
                  'issues': ['LICENSE_TEXT_MISSING'], 'files': []}
        if provenance is not None:
            record['provenance'] = copy.deepcopy(provenance)
        if name == 'r-efi':
            checksum = 'd027e91dbc9cdbb2f1190068e498bd6b61cff022b6a032b191021ba658d96111'
            record['files'] = [{'source_path': 'AUTHORS', 'sha256': checksum, 'file': 'licenses/' + checksum + '.txt'}]
        packages.append(record)
    return {'format_version': 1, 'evidence_status': 'incomplete', 'issues': [], 'packages': packages}

class GapTests(unittest.TestCase):
    def test_exact_four_bound_gaps_are_documented_not_cleared(self):
        report = fixture()
        before = copy.deepcopy(report)
        status, gaps = m.classify(report)
        self.assertEqual(status, m.DOCUMENTED)
        self.assertEqual(len(gaps), 4)
        self.assertEqual(report, before)
        self.assertTrue(all(g['reason'] == 'LICENSE_TEXT_MISSING' for g in gaps))

    def test_unknown_package_version_checksum_issue_or_provenance_rejected(self):
        for change in ({'name': 'other'}, {'version': '0.6.9'}, {'archive_sha256': '0'*64},
                       {'issues': ['ARCHIVE_MISSING']}, {'issues': ['LICENSE_TEXT_MISSING','EXTRA']},
                       {'provenance': {'commit': '0'*40}}, {'purl': 'pkg:cargo/other@1'}, {'declared_license': ''}):
            report = fixture()
            report['packages'][0].update(change)
            with self.subTest(change=change):
                self.assertEqual(m.classify(report), (m.INCOMPLETE, []))

    def test_missing_source_version_manifest_or_root_issue_rejected(self):
        for key in ('format_version', 'packages', 'issues'):
            report = fixture(); del report[key]
            self.assertEqual(m.classify(report), (m.INCOMPLETE, []))
        for key in ('version', 'archive_sha256', 'files'):
            report = fixture(); del report['packages'][0][key]
            self.assertEqual(m.classify(report), (m.INCOMPLETE, []))
        report = fixture(); report['issues'] = ['CACHE_MISSING']
        self.assertEqual(m.classify(report), (m.INCOMPLETE, []))

    def test_extra_unbound_package_source_not_ignored(self):
        report = fixture()
        report['packages'].append({'ecosystem':'cargo','name':'extra','version':'1','files':[],'issues':[]})
        self.assertEqual(m.classify(report), (m.INCOMPLETE, []))

    def test_duplicate_package_rejected(self):
        report = fixture(); report['packages'].append(copy.deepcopy(report['packages'][0]))
        self.assertEqual(m.classify(report), (m.INCOMPLETE, []))

    def test_repaired_subset_allowed_without_erasing_other_gaps(self):
        report = fixture(); report['packages'][1]['issues'] = []
        status, gaps = m.classify(report)
        self.assertEqual(status, m.DOCUMENTED)
        self.assertEqual(len(gaps), 3)

    def test_existing_r_efi_notice_must_not_disappear(self):
        report = fixture()
        record = next(p for p in report['packages'] if p['name'] == 'r-efi')
        record['files'] = []
        self.assertEqual(m.classify(report), (m.INCOMPLETE, []))

    def test_complete_label_cannot_hide_issues(self):
        report = fixture(); report['evidence_status'] = m.COMPLETE
        self.assertEqual(m.classify(report), (m.INCOMPLETE, []))

if __name__ == '__main__':
    unittest.main()
