#!/usr/bin/env python3
"""部署模板/秘密初始化的失效关闭回归；无守护进程或真实账户变更。"""
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('initializer', ROOT / 'deploy/server/init-private.py')
init = importlib.util.module_from_spec(spec)
spec.loader.exec_module(init)


class DeploymentTests(unittest.TestCase):
    def test_new_secret_permissions_and_no_replacement(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            init.generate(root)
            private = root / '.secrets'
            self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o700)
            before = {p.name: p.read_bytes() for p in private.iterdir()}
            self.assertEqual(len(before), 5)
            for p in private.iterdir():
                self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o444)
            with self.assertRaises(FileExistsError):
                init.generate(root)
            self.assertEqual(before, {p.name: p.read_bytes() for p in private.iterdir()})

    def test_symlink_and_unsafe_ancestor_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / 'real').mkdir()
            (root / 'alias').symlink_to(root / 'real')
            with self.assertRaises(OSError):
                init.generate(root / 'alias')
            (root / 'real').chmod(0o777)
            with self.assertRaises(ValueError):
                init.generate(root / 'real')
            self.assertFalse((root / 'real/.secrets').exists())

    def test_tls_safe_copy_preserves_original_and_rejects_existing(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); source = root / 'source'; source.mkdir(mode=0o700)
            cert = source / 'cert.pem'; key = source / 'key.pem'
            cert.write_bytes(b'synthetic certificate'); key.write_bytes(b'synthetic private key')
            cert.chmod(0o644); key.chmod(0o600)
            before = (key.stat().st_ino, key.stat().st_mode, key.read_bytes())
            init.stage_tls(root, cert, key)
            self.assertEqual(before, (key.stat().st_ino, key.stat().st_mode, key.read_bytes()))
            self.assertEqual((root / '.tls/private-key.pem').read_bytes(), key.read_bytes())
            self.assertEqual(stat.S_IMODE((root / '.tls').stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((root / '.tls/private-key.pem').stat().st_mode), 0o444)
            with self.assertRaises(FileExistsError):
                init.stage_tls(root, cert, key)

    def test_tls_rejects_public_key_symlink_and_hardlink(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); cert = root / 'cert'; key = root / 'key'
            cert.write_bytes(b'cert'); key.write_bytes(b'key')
            key.chmod(0o644)
            with self.assertRaises(ValueError):
                init.stage_tls(root, cert, key)
            key.chmod(0o600)
            (root / 'alias').symlink_to(key)
            with self.assertRaises(OSError):
                init.stage_tls(root, cert, root / 'alias')
            os.link(key, root / 'hardlink')
            with self.assertRaises(ValueError):
                init.stage_tls(root, cert, key)
            self.assertFalse((root / '.tls').exists())

    def test_existing_secret_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / 'sentinel').write_text('untouched')
            (root / '.secrets').symlink_to(root / 'sentinel')
            with self.assertRaises(FileExistsError):
                init.generate(root)
            self.assertEqual((root / 'sentinel').read_text(), 'untouched')

    def test_compose_and_runtime_context(self):
        deploy = ROOT / 'deploy/server'
        config = yaml.safe_load((deploy / 'compose.yaml').read_text())
        for name, service in config['services'].items():
            if name == 'gateway':
                self.assertEqual(service['ports'], ['127.0.0.1:18080:8080'])
            else:
                self.assertFalse(service.get('ports'))
            if 'build' not in service:
                self.assertIn('@sha256:', service['image'])
        self.assertTrue(config['networks']['backend']['internal'])
        self.assertFalse(config['networks']['egress']['internal'])
        self.assertEqual(config['services']['device-server']['networks'], ['backend', 'egress'])
        for name in ('postgres', 'redis', 'migrate'):
            self.assertEqual(config['services'][name]['networks'], ['backend'])
        dockerfile = (deploy / 'Dockerfile').read_text()
        self.assertNotIn('COPY src', dockerfile)
        self.assertNotIn('go build', dockerfile)
        self.assertNotIn('apk add', dockerfile)
        self.assertIn('COPY bin/', dockerfile)
        self.assertEqual((deploy / 'Dockerfile.dockerignore').read_text().splitlines()[0], '**')
        self.assertNotIn('allow-loopback', ''.join(p.read_text() for p in deploy.rglob('*') if p.is_file() and p.suffix != '.pyc'))

    @unittest.skipUnless(os.environ.get('PEERLOOM_NONOWNER_TEST') == '1', 'explicit isolated CI sudo probe required')
    def test_actual_other_uid_cannot_read_host_secret(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            # The outer path is traversable; only the new .secrets 0700 prevents access.
            root.chmod(0o755)
            init.generate(root)
            probe = subprocess.run(['sudo', '-n', '-u', 'nobody', 'test', '-r', str(root / '.secrets/replay_key')],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            self.assertEqual(probe.returncode, 1)
            public = root / 'readable'
            public.write_text('nonsecret')
            public.chmod(0o644)
            control = subprocess.run(['sudo', '-n', '-u', 'nobody', 'test', '-r', str(public)], check=False)
            self.assertEqual(control.returncode, 0)


if __name__ == '__main__':
    unittest.main()
