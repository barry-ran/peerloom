#!/usr/bin/env python3
"""核验固定 nix 原包与两个官方 cfg 回移；校验通过不等于 Apple 编译/运行通过。"""
import difflib
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'third_party/rust/nix-0.31.3'
MANIFEST_SHA = 'aae87372c776e42ad1b8e756fa20c707266a99e6b884d08a4b0d7acd258c1054'
ARCHIVE_SHA = 'cf20d2fde8ff38632c426f1165ed7436270b44f199fc55284c38276f9db47c3d'
UPSTREAM_PATCH_SHA = '2b7e32002378680ad31b55c6a0e601c0668dab3121ea938a8d4bf970b1ee7e25'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify(base):
    encoded = (base / '来源.json').read_bytes()
    assert sha(encoded) == MANIFEST_SHA, 'source manifest changed'
    manifest = json.loads(encoded)
    assert manifest['archive']['sha256'] == ARCHIVE_SHA
    assert manifest['upstream_patch']['sha256'] == UPSTREAM_PATCH_SHA
    assert manifest['package'] == {'name': 'nix', 'version': '0.31.3', 'declared_license': 'MIT'}
    assert sha((base / '上游补丁.patch').read_bytes()) == UPSTREAM_PATCH_SHA
    assert len(manifest['modifications']) == 2
    crate = base / 'crate'
    paths = list(crate.rglob('*'))
    assert not any(p.is_symlink() for p in paths), 'symlink in source tree'
    actual = {p.relative_to(crate).as_posix() for p in paths if p.is_file()}
    expected = {record['path'] for record in manifest['files']}
    assert actual == expected and 'LICENSE' in actual, 'source file inventory mismatch'
    original = {}
    changes = {entry['path']: entry for entry in manifest['modifications']}
    assert set(changes) == {'src/sys/socket/mod.rs', 'src/sys/socket/sockopt.rs'}
    for entry in manifest['files']:
        path = PurePosixPath(entry['path'])
        assert not path.is_absolute() and '..' not in path.parts
        content = (crate / path).read_bytes()
        assert sha(content) == entry['sha256'], 'source content changed'
        if entry['path'] in changes:
            change = changes[entry['path']]
            text = content.decode()
            assert text.count(change['new']) == 1
            content = text.replace(change['new'], change['old']).encode()
        assert sha(content) == entry['upstream_sha256'], 'change outside approved backport'
        original[entry['path']] = content
    applied = ''
    for entry in manifest['modifications']:
        path = entry['path']
        applied += ''.join(difflib.unified_diff(original[path].decode().splitlines(keepends=True),
                             (crate / path).read_text().splitlines(keepends=True), fromfile='a/' + path, tofile='b/' + path))
    assert (base / '应用补丁.patch').read_text() == applied
    assert sha(applied.encode()) == manifest['applied_patch']['sha256']


class VendoredNixTests(unittest.TestCase):
    def test_verified_original_license_and_exact_two_source_changes(self):
        verify(BASE)

    def altered(self, action):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / 'nix'
            shutil.copytree(BASE, base)
            action(base)
            with self.assertRaises(AssertionError):
                verify(base)

    def test_changed_source_rejected(self):
        self.altered(lambda base: (base / 'crate/src/lib.rs').write_text('// tampered\n'))

    def test_extra_source_rejected(self):
        self.altered(lambda base: (base / 'crate/extra.rs').write_text('// unlisted\n'))

    def test_manifest_and_upstream_patch_are_pinned(self):
        self.altered(lambda base: (base / '来源.json').write_text('{}'))

    def test_symlink_rejected(self):
        self.altered(lambda base: (base / 'crate/link').symlink_to('LICENSE'))


if __name__ == '__main__':
    unittest.main()
