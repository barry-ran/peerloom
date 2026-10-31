#!/usr/bin/env python3
"""核验 webrtc 固定原包、单次 TURN 排空补丁与精确构建闭包。"""
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'third_party/rust/webrtc-0.21.1'
MANIFEST_SHA = '59f61460db8cf5ff31c4723bde65a58d37033c4d7797379a0d91ca5b1f8db6ac'
ARCHIVE_SHA = 'b621e736302bef784948cc8d8099fd0a8fdb5757693c80a344ffbe38c49387d2'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify(base):
    encoded = (base / '来源.json').read_bytes()
    assert sha(encoded) == MANIFEST_SHA, 'source manifest changed'
    manifest = json.loads(encoded)
    assert manifest['archive']['sha256'] == ARCHIVE_SHA
    assert manifest['package'] == {'name': 'webrtc', 'version': '0.21.1', 'declared_license': 'MIT/Apache-2.0'}
    assert manifest['patch']['modified_files'] == ['Cargo.toml', 'src/peer_connection/driver.rs', 'src/peer_connection/mod.rs']
    patch = base / '应用补丁.patch'
    assert sha(patch.read_bytes()) == manifest['patch']['sha256']
    crate = base / 'crate'
    paths = list(crate.rglob('*'))
    assert not any(p.is_symlink() for p in paths), 'symlink in source tree'
    actual = {p.relative_to(crate).as_posix() for p in paths if p.is_file()}
    expected = {entry['path'] for entry in manifest['files']}
    assert actual == expected and {'LICENSE-APACHE', 'LICENSE-MIT'} <= actual
    excluded = {entry['path'] for entry in manifest['excluded']}
    assert len(expected) == 26 and len(excluded) == 159
    assert not excluded & expected
    assert expected == {item['path'] for item in manifest['files']}
    assert all(name.startswith('src/') or name in {'Cargo.toml','README.md','LICENSE-MIT','LICENSE-APACHE'} for name in expected)
    import tomllib
    info = tomllib.loads((crate/'Cargo.toml').read_text(encoding='utf-8'))
    assert 'example' not in info and 'test' not in info and 'dev-dependencies' not in info
    assert info['package']['autoexamples'] is False and info['package']['autotests'] is False
    assert 'codecov.yml' in excluded and 'Cargo.lock' in excluded
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
        upstream = tomllib.loads((restored/'Cargo.toml').read_text(encoding='utf-8'))
        assert info['dependencies'] == upstream['dependencies']
        assert info['features'] == upstream['features']
        assert info['package'] == upstream['package']
        assert info['lib'] == upstream['lib']



class VendoredWebrtcTests(unittest.TestCase):
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

    def test_excluded_upstream_test_and_ci_rejected(self):
        for name in ('tests/peer_connection_test.rs', '.github/workflows/cargo.yml', 'Cargo.lock'):
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
