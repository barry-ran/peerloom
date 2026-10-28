#!/usr/bin/env python3
"""Actual local Git checkout regression; no network or source repository changes."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CheckoutEvidenceTests(unittest.TestCase):
    def test_autocrlf_preserves_upstream_lf_crlf_and_mixed_bytes(self):
        fixtures = {
            'scripts/testdata/maven-gap-proof/poms/fixture.xml': b'Original POM LF\n',
            'scripts/testdata/maven-gap-proof/licenses/fixture.txt': b'Original license CRLF\r\nCopyright\r\n',
            'scripts/testdata/maven-gap-proof/licenses/mixed.txt': b'Original mixed\r\nNotice\n',
            'third_party/license-evidence/manifest.json': b'{"fixture": true}\n',
            'third_party/rust/nix-0.31.3/crate/LICENSE': b'Original upstream CRLF\r\nCopyright\r\n',
            'third_party/rust/rtc-0.21.1/crate/LICENSE': b'Original mixed\r\nSecond line\n',
            'third_party/rust/rtc-0.21.1/source.json': b'Pinned manifest LF\n',
            'infra/migrations/000001_fixture.up.sql': b'Original hash-bound bytes\r\nDo not normalize\n',
            'src/device-sdk/Cargo.toml': b'Original hash-bound bytes\r\nDo not normalize\n',
            'src/device-sdk/Cargo.lock': b'Original hash-bound bytes\r\nDo not normalize\n',
            'src/device-server/go.mod': b'Original hash-bound bytes\r\nDo not normalize\n',
            'src/device-server/go.sum': b'Original hash-bound bytes\r\nDo not normalize\n',
            'src/admin-web/package-lock.json': b'Original hash-bound bytes\r\nDo not normalize\n',
            'src/device-sdk/device-ffi/include/device_sdk.h': b'Original hash-bound bytes\r\nDo not normalize\n',
            'bindings/android/gradle/wrapper/来源.json': b'Original hash-bound bytes\r\nDo not normalize\n',
            'bindings/android/gradle/wrapper/许可证.txt': b'Original hash-bound bytes\r\nDo not normalize\n',
            'LICENSE': b'Original hash-bound bytes\r\nDo not normalize\n',
        }
        with tempfile.TemporaryDirectory(prefix='peerloom-checkout-') as temp:
            root = Path(temp)
            def git(*args):
                return subprocess.run(['git', '-C', str(root), *args], check=True,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30).stdout
            git('init', '-q')
            for name, data in fixtures.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            # Index the original bytes, never normalized bytes.
            git('-c', 'core.autocrlf=false', 'add', '--force', '.')
            for name in fixtures:
                (root/name).unlink()
            git('-c', 'core.autocrlf=true', 'checkout-index', '--all', '--force')
            self.assertNotEqual((root/'third_party/license-evidence/manifest.json').read_bytes(),
                                fixtures['third_party/license-evidence/manifest.json'])
            (root/'.gitattributes').write_bytes((ROOT/'.gitattributes').read_bytes())
            for name in fixtures:
                (root/name).unlink()
            git('-c', 'core.autocrlf=true', 'checkout-index', '--all', '--force')
            for name, data in fixtures.items():
                with self.subTest(path=name):
                    self.assertEqual((root/name).read_bytes(), data)
                    self.assertEqual(git('show', ':'+name), data)
            # This scope must not disable conversion for unrelated project files.
            result = git('check-attr', 'text', '--', 'docs/unrelated.md')
            self.assertIn(b': text: unspecified', result)


if __name__ == '__main__':
    unittest.main()
