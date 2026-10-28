#!/usr/bin/env python3
"""Controlled real provenance fixtures, copied to an isolated temporary root."""
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('gen', Path(__file__).with_name('generate-third-party.py'))
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)

class VendorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.patches = {}
        # The integration runner may supply a root with both reviewed vendors.
        import os
        fixtures = os.environ.get('PEERLOOM_VENDOR_FIXTURES', str(Path(__file__).resolve().parents[1]))
        for name, version in [('nix', '0.31.3'), ('rtc', '0.21.1')]:
            base = f'third_party/rust/{name}-{version}'
            source = Path(fixtures) / base
            if not source.is_dir():
                self.fail('Both reviewed vendor fixture directories are required')
            shutil.copytree(source, self.root / base)
            self.patches[name] = {'path': '../../' + base + '/crate'}
        self.base = self.root / 'third_party/rust/nix-0.31.3'

    def call(self, name='nix', version='0.31.3'):
        record, blobs = gen.package('cargo', name, version), {}
        gen.cargo_vendor(record, self.root, self.patches, blobs)
        return record, blobs

    def test_both_modified_components_in_sbom(self):
        records, blobs = [], {}
        for name, version in [('nix', '0.31.3'), ('rtc', '0.21.1')]:
            record, contents = self.call(name, version)
            records.append(record); blobs.update(contents)
        files, incomplete = gen.render(records, blobs, [], {})
        self.assertFalse(incomplete)
        components = json.loads(files['sbom.cdx.json'])['components']
        self.assertEqual({x['name'] for x in components}, {'nix', 'rtc'})
        for item in components:
            self.assertNotIn('hashes', item)
            self.assertTrue(any(x['name'] == 'peerloom:modified-vendor-provenance' for x in item['properties']))

    def test_collect_resolves_locked_path_patches(self):
        from unittest.mock import patch
        sdk = self.root / 'src/device-sdk'
        sdk.mkdir(parents=True)
        (self.root / 'src/device-server').mkdir()
        (self.root / 'src/device-server/go.sum').write_text('')
        (sdk / 'Cargo.toml').write_text('[workspace]\nmembers=[]\n[patch.crates-io]\nnix={path="../../third_party/rust/nix-0.31.3/crate"}\nrtc={path="../../third_party/rust/rtc-0.21.1/crate"}\n')
        (sdk / 'Cargo.lock').write_text('version=4\n[[package]]\nname="nix"\nversion="0.31.3"\n[[package]]\nname="rtc"\nversion="0.21.1"\n')
        with patch.object(gen, 'run', side_effect=['', str(self.root / 'go-cache')]):
            records, blobs, issues = gen.collect(self.root)
        self.assertEqual(len(records), 2)
        self.assertFalse(issues)
        self.assertTrue(all(not item['issues'] and item['vendor_provenance'] for item in records))

    def test_unknown_patch(self):
        with self.assertRaisesRegex(gen.EvidenceError, 'UNREVIEWED'): self.call('unknown', '1.0.0')

    def test_malicious_patch_paths(self):
        for path in ['/tmp/crate', '../../../../tmp/crate', '../../third_party/rust/nix-0.31.3/./crate']:
            with self.subTest(path=path):
                self.patches['nix'] = {'path': path}
                with self.assertRaisesRegex(gen.EvidenceError, 'PATH_MISMATCH'): self.call()

    def test_symlink_ancestor(self):
        crate = self.base / 'crate'
        crate.rename(self.base / 'elsewhere')
        crate.symlink_to('elsewhere', target_is_directory=True)
        with self.assertRaisesRegex(gen.EvidenceError, 'SYMLINK'): self.call()

    def test_missing_license(self):
        (self.base / 'crate/LICENSE').unlink()
        with self.assertRaisesRegex(gen.EvidenceError, 'MISSING'): self.call()

    def test_tampered_source(self):
        (self.base / 'crate/src/lib.rs').write_text('tampered')
        with self.assertRaisesRegex(gen.EvidenceError, 'CONTENT_MISMATCH'): self.call()

    def test_tampered_provenance(self):
        (self.base / '来源.json').write_text('{}')
        with self.assertRaisesRegex(gen.EvidenceError, 'PROVENANCE_MISMATCH'): self.call()

    def test_extra_source(self):
        (self.base / 'crate/extra.rs').write_text('unexpected')
        with self.assertRaisesRegex(gen.EvidenceError, 'UNTRACKED'): self.call()

    def test_tampered_patch(self):
        (self.base / '应用补丁.patch').write_text('changed')
        with self.assertRaisesRegex(gen.EvidenceError, 'PATCH_CHECKSUM'): self.call()

if __name__ == '__main__': unittest.main()
