#!/usr/bin/env python3
"""实际包验收控制器的恶意归档、清理与运行路径负测。"""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('package_test', ROOT / 'scripts/test-server-package.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def archive(path, entries):
    with tarfile.open(path, 'w:gz') as out:
        for name, data, mode, kind in entries:
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.type = len(data), mode, kind
            out.addfile(info, io.BytesIO(data))


def fixture(path):
    names = {'bin/' + n for n in m.BINS} | set(m.SQL) | {
        'deploy/Dockerfile', 'deploy/Dockerfile.dockerignore', 'deploy/init-private.py',
        'deploy/compose.yaml', 'deploy/compose.tls.yaml', 'deploy/gateway/nginx-tls.conf'}
    entries = [(n, b'synthetic bytes', 0o755 if n.startswith('bin/') else 0o644, tarfile.REGTYPE)
               for n in sorted(names)]
    checks = ''.join(hashlib.sha256(data).hexdigest() + '  ' + name + '\n'
                     for name, data, _, _ in entries).encode()
    entries.append(('SHA256SUMS', checks, 0o644, tarfile.REGTYPE))
    archive(path, entries)


class ControllerTests(unittest.TestCase):
    def test_safe_complete_extract(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); target = root / 'out'; target.mkdir()
            fixture(root / 'input.tar.gz')
            m.extract(root / 'input.tar.gz', target)
            self.assertTrue((target / 'bin/device-server').stat().st_mode & 0o111)

    def test_reject_path_links_modes_and_source(self):
        cases = [('../escape', tarfile.REGTYPE, 0o644), ('/absolute', tarfile.REGTYPE, 0o644),
                 ('bin/alias', tarfile.SYMTYPE, 0o644), ('bin/hard', tarfile.LNKTYPE, 0o644),
                 ('bin/setuid', tarfile.REGTYPE, 0o4755), ('src/private.go', tarfile.REGTYPE, 0o644)]
        for name, kind, mode in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as raw:
                root = Path(raw); target = root / 'out'; target.mkdir()
                archive(root / 'bad.tar.gz', [(name, b'', mode, kind)])
                with self.assertRaises(m.Failure):
                    m.extract(root / 'bad.tar.gz', target)

    def test_reject_duplicate_and_bad_checksum(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); target = root / 'out'; target.mkdir()
            archive(root / 'bad.tar.gz', [('same', b'', 0o644, tarfile.REGTYPE)] * 2)
            with self.assertRaises(m.Failure):
                m.extract(root / 'bad.tar.gz', target)

    def test_corrupted_complete_payload_checksum_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); target = root / 'out'; target.mkdir()
            good = root / 'good.tar.gz'; fixture(good)
            entries = []
            with tarfile.open(good, 'r:gz') as source:
                for entry in source:
                    data = source.extractfile(entry).read()
                    if entry.name == 'bin/device-server':
                        data = b'tampered executable'
                    entries.append((entry.name, data, entry.mode, tarfile.REGTYPE))
            archive(root / 'bad.tar.gz', entries)
            with self.assertRaisesRegex(m.Failure, 'checksum mismatch'):
                m.extract(root / 'bad.tar.gz', target)

    def test_unknown_build_outcome_image_cleanup_and_safe_errors(self):
        image = 'peerloom-package-' + 'd' * 32 + ':runtime'
        calls = []
        def run(args, **kwargs):
            calls.append(args)
            return image.encode() if 'ls' in args else b''
        m.remove_owned_image(run, image)
        self.assertEqual(calls[-1], ['docker', 'image', 'rm', image])
        with self.assertRaises(m.Failure):
            m.remove_owned_image(run, 'foreign:latest')
        self.assertEqual(m.safe_diagnostic(RuntimeError('secret-token-response')), 'RuntimeError')
        self.assertEqual(m.safe_diagnostic(m.Failure('migration versions mismatch')), 'migration versions mismatch')

    def test_interruption_ignores_repeat_until_cleanup(self):
        original = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        try:
            with self.assertRaises(m.Failure):
                m.interrupted(signal.SIGTERM, None)
            os.kill(os.getpid(), signal.SIGTERM)
            self.assertEqual(signal.getsignal(signal.SIGTERM), signal.SIG_IGN)
        finally:
            for sig, handler in original.items():
                signal.signal(sig, handler)

    def test_invoke_timeout_reaps_own_child(self):
        import subprocess
        import sys
        with tempfile.TemporaryDirectory() as raw:
            pidfile = Path(raw) / 'pid'
            code = 'import os,time,pathlib;pathlib.Path(' + repr(str(pidfile)) + ').write_text(str(os.getpid()));time.sleep(30)'
            with self.assertRaises(subprocess.TimeoutExpired):
                m.invoke([sys.executable, '-c', code], timeout=0.3)
            pid = int(pidfile.read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def test_exact_owned_container_cleanup(self):
        name = 'peerloom-package-' + 'a' * 32 + '-image-probe'
        calls = []
        def run(args, **kwargs):
            calls.append(args)
            return name.encode() if 'ls' in args else b''
        m.remove_owned_container(run, name)
        self.assertEqual(calls[-1], ['docker', 'container', 'rm', '-f', name])
        with self.assertRaises(m.Failure):
            m.remove_owned_container(run, 'unrelated-container')

    def test_owned_container_unknown_or_cleanup_failure_fails(self):
        name = 'peerloom-package-' + 'b' * 32 + '-oneoff-1'
        with self.assertRaises(m.Failure):
            m.remove_owned_container(lambda *a, **k: b'foreign', name)
        def fail(args, **kwargs):
            if 'ls' in args:
                return name.encode()
            raise m.Failure('cleanup failure')
        with self.assertRaises(m.Failure):
            m.remove_owned_container(fail, name)

    def test_absent_owned_container_is_not_removed(self):
        calls = []
        def run(args, **kwargs):
            calls.append(args)
            return b''
        m.remove_owned_container(run, 'peerloom-package-' + 'c' * 32 + '-oneoff-0')
        self.assertEqual(len(calls), 1)

    def test_real_sigterm_still_cleans_owned_probe_and_project(self):
        from types import SimpleNamespace
        calls = []
        probe_name = None
        def run(args, **kwargs):
            nonlocal probe_name
            calls.append(args)
            if 'config' in args:
                package = str(Path(args[args.index('-f') + 1]).parent.parent)
                return json.dumps({'services': {n: {'build': {'context': package}}
                                                for n in ('device-server', 'migrate')}}).encode()
            if args[:3] == ['docker', 'run', '--rm']:
                probe_name = args[args.index('--name') + 1]
                os.kill(os.getpid(), signal.SIGTERM)
                self.fail('SIGTERM did not interrupt')
            if args[:3] == ['docker', 'container', 'ls']:
                os.kill(os.getpid(), signal.SIGTERM)  # Repeat during cleanup must be ignored.
                return probe_name.encode()
            if args[:3] == ['docker', 'image', 'ls']:
                return args[args.index('--filter') + 1].removeprefix('reference=').encode()
            return b''
        def certificates(directory):
            directory.mkdir()
            (directory / 'server.key').write_bytes(b'synthetic private input')
            (directory / 'server.crt').write_bytes(b'synthetic certificate input')
            return directory / 'ca.crt'
        client = SimpleNamespace(require_local_docker=lambda: None,
                                 certificates=certificates,
                                 validate_rendered=lambda raw: None, ORIGIN='https://127.0.0.1:18443')
        old = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        try:
            signal.signal(signal.SIGTERM, m.interrupted)
            with tempfile.TemporaryDirectory() as raw:
                payload = Path(raw) / 'fixture.tar.gz'
                fixture(payload)
                with patch.object(m, 'invoke', run), self.assertRaises(m.Failure):
                    m.execute(payload, client)
            self.assertIn(['docker', 'container', 'rm', '-f', probe_name], calls)
            self.assertTrue(any('down' in c and '--volumes' in c for c in calls))
            self.assertTrue(any(c[:3] == ['docker', 'image', 'rm'] for c in calls))
        finally:
            for sig, handler in old.items():
                signal.signal(sig, handler)

    def test_egress_probe_mode_namespace_and_negative_ca(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw); package = directory / 'package'; package.mkdir()
            (directory / 'tls').mkdir(); (directory / 'tls/ca.crt').write_bytes(b'ca')
            def build(args, **kwargs):
                output = Path(args[args.index('-o') + 1]); output.write_bytes(b'probe'); output.chmod(0o700)
                return b''
            def certificates(path):
                path.mkdir(); (path / 'ca.crt').write_bytes(b'wrong ca'); return path / 'ca.crt'
            project = 'peerloom-package-' + 'e' * 32
            calls = []
            def run(args, **kwargs):
                calls.append(args)
                if '{{.State.Health.Status}}' in args:
                    return b'healthy'
                if '{{json .NetworkSettings.Networks}}' in args:
                    return json.dumps({project + '_egress': {'IPAddress': '172.30.0.2'}}).encode()
                return b''
            owned = []
            with patch.object(m, 'invoke', build):
                m.verify_egress(run, SimpleNamespace(certificates=certificates), directory, package,
                                project, 'runtime', 'owned-server-id', 'fixed-nginx', owned)
            self.assertEqual((directory / 'egress-client').stat().st_mode & 0o777, 0o555)
            self.assertEqual(len(owned), 3)
            clients = [c for c in calls if 'container:owned-server-id' in c]
            self.assertEqual(len(clients), 2)
            self.assertNotIn('--reject', clients[0]); self.assertIn('--reject', clients[1])
            self.assertTrue(all('--read-only' in c for c in clients))

    def test_no_repository_in_docker_context_contract(self):
        source = (ROOT / 'scripts/test-server-package.py').read_text()
        self.assertIn("extract(payload, package)", source)
        self.assertIn("!= package", source)
        self.assertNotIn("['build', 'context'] = str(ROOT)", source)
        self.assertIn("['down', '--volumes', '--remove-orphans'", source)
        self.assertIn("signal.signal(signal.SIGTERM, signal.SIG_IGN)", source)


if __name__ == '__main__':
    unittest.main()
