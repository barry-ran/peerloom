#!/usr/bin/env python3
"""核验 rtc 固定原包、最小本地补丁与显式排除的非构建示例。"""
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'third_party/rust/rtc-0.21.1'
MANIFEST_SHA = '9072d1f2da22f6ea63a8fabccad61c0b18a3494d58b0d20d85533c4475d65b24'
ARCHIVE_SHA = '4e2ca201de5ccc83aa3c08d49a2f08d7ed0aeeb2052fb1ccc517a8b77a6927ce'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify(base):
    encoded = (base / '来源.json').read_bytes()
    assert sha(encoded) == MANIFEST_SHA, 'source manifest changed'
    manifest = json.loads(encoded)
    assert manifest['archive']['sha256'] == ARCHIVE_SHA
    assert manifest['package'] == {'name': 'rtc', 'version': '0.21.1', 'declared_license': 'MIT/Apache-2.0'}
    assert manifest['patch']['modified_files'] == ['Cargo.toml', 'src/data_channel/internal.rs']
    patch = base / '应用补丁.patch'
    assert sha(patch.read_bytes()) == manifest['patch']['sha256']
    crate = base / 'crate'
    paths = list(crate.rglob('*'))
    assert not any(p.is_symlink() for p in paths), 'symlink in source tree'
    actual = {p.relative_to(crate).as_posix() for p in paths if p.is_file()}
    expected = {entry['path'] for entry in manifest['files']}
    assert actual == expected and {'LICENSE-APACHE', 'LICENSE-MIT'} <= actual
    excluded = {entry['path'] for entry in manifest['excluded']}
    assert len(expected) == 216 and len(excluded) == 151
    metadata = {'codecov.yml', '.github/workflows/cargo.yml', '.github/workflows/grcov.yml', '.github/workflows/semver.yml'}
    private_fixtures = {'tests/dtls_rsa_certificate.rs', 'tests/testdata/rsa_2048_answerer_key.pem', 'tests/testdata/rsa_2048_offerer_key.pem'}
    assert not excluded & expected and metadata | private_fixtures <= excluded
    assert all(name.startswith('examples/') or name in metadata | private_fixtures for name in excluded)
    assert 'dtls_rsa_certificate' not in (crate / 'Cargo.toml').read_text()
    assert 'dtls_rsa_certificate' not in (crate / 'Cargo.toml.orig').read_text()
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


class VendoredRtcTests(unittest.TestCase):
    def test_original_sources_licenses_exclusions_and_exact_patch(self):
        verify(BASE)

    def altered(self, action):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / 'rtc'
            shutil.copytree(BASE, base)
            action(base)
            with self.assertRaises(AssertionError):
                verify(base)

    def test_excluded_coverage_metadata_rejected(self):
        self.altered(lambda b: (b / 'crate/codecov.yml').write_text('unrelated upstream metadata'))

    def test_excluded_private_key_fixtures_and_dependent_test_rejected(self):
        for name in ('tests/dtls_rsa_certificate.rs', 'tests/testdata/rsa_2048_answerer_key.pem', 'tests/testdata/rsa_2048_offerer_key.pem'):
            def add_omitted(base):
                path = base / 'crate' / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('synthetic excluded fixture marker; no key material')
            with self.subTest(path=name):
                self.altered(add_omitted)

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
