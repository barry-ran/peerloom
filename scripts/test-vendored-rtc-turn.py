#!/usr/bin/env python3
"""Verify the pinned rtc-turn archive, licenses and exact local patch."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'third_party/rust/rtc-turn-0.21.1'
MANIFEST_SHA = 'f9233cb6bc88990aeaba13993717060f0b6fcd0d08591f51c22e743d3453046f'
ARCHIVE_SHA = 'c53078a0696df5a3a5e4947bc550c5e903b59803b252f1d39062d637ebd3d17e'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify(base):
    encoded = (base / '来源.json').read_bytes()
    assert sha(encoded) == MANIFEST_SHA, 'source manifest changed'
    manifest = json.loads(encoded)
    assert manifest['archive']['sha256'] == ARCHIVE_SHA
    assert manifest['package'] == {'name': 'rtc-turn', 'version': '0.21.1', 'declared_license': 'MIT/Apache-2.0'}
    assert manifest['patch']['modified_files'] == ['src/client/binding.rs', 'src/client/relay.rs', 'src/client/client_test.rs']
    patch = base / '应用补丁.patch'
    assert sha(patch.read_bytes()) == manifest['patch']['sha256']
    crate = base / 'crate'
    paths = list(crate.rglob('*'))
    assert not any(p.is_symlink() for p in paths), 'symlink in source tree'
    actual = {p.relative_to(crate).as_posix() for p in paths if p.is_file()}
    expected = {entry['path'] for entry in manifest['files']}
    assert actual == expected and {'LICENSE-APACHE', 'LICENSE-MIT'} <= actual
    assert manifest['archive']['vcs_commit'] == '2a732df55ca4bcf26b80914fa0f570cfaf74cfcb'
    assert manifest['archive']['url'] == 'https://static.crates.io/crates/rtc-turn/rtc-turn-0.21.1.crate'
    assert len(expected) == 45
    assert not manifest.get('excluded', [])
    for license_name in ('LICENSE-MIT', 'LICENSE-APACHE'):
        assert (crate / license_name).read_bytes() == (ROOT / 'third_party/rust/rtc-0.21.1/crate' / license_name).read_bytes()
    with tempfile.TemporaryDirectory() as directory:
        restored = Path(directory)
        for entry in manifest['files']:
            name = PurePosixPath(entry['path'])
            assert not name.is_absolute() and '..' not in name.parts
            content = (crate / name).read_bytes()
            assert sha(content) == entry['sha256'], 'source content changed'
            if str(name) in manifest['patch']['modified_files']:
                destination = restored / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content)
            else:
                assert sha(content) == entry['upstream_sha256'], 'unapproved source difference'
        # A pinned, reviewed patch must reverse exactly, not merely match new hashes.
        result = subprocess.run(['patch', '--batch', '--fuzz=0', '-R', '-p1', '-i', str(patch.resolve())],
                                cwd=restored, capture_output=True, timeout=10)
        assert result.returncode == 0, 'cannot restore exact upstream files'
        for entry in manifest['files']:
            if entry['path'] in manifest['patch']['modified_files']:
                assert sha((restored / entry['path']).read_bytes()) == entry['upstream_sha256']


class VendoredRtcTurnTests(unittest.TestCase):
    def test_original_sources_licenses_exclusions_and_exact_patch(self):
        verify(BASE)

    def altered(self, action):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / 'rtc'
            shutil.copytree(BASE, base)
            action(base)
            with self.assertRaises(AssertionError):
                verify(base)

    def test_changed_license_rejected(self):
        self.altered(lambda b: (b / 'crate/LICENSE-MIT').write_text('changed license'))

    def test_changed_library_rejected(self):
        self.altered(lambda b: (b / 'crate/src/lib.rs').write_text('// tampered\n'))

    def test_unlisted_source_rejected(self):
        self.altered(lambda b: (b / 'crate/extra.rs').write_text('// unlisted\n'))

    def test_changed_manifest_rejected(self):
        self.altered(lambda b: (b / '来源.json').write_text('{}'))

    def test_changed_patch_rejected(self):
        self.altered(lambda b: (b / '应用补丁.patch').write_text(''))

    def test_symlink_rejected(self):
        self.altered(lambda b: (b / 'crate/link').symlink_to('LICENSE-MIT'))


if __name__ == '__main__':
    unittest.main()
