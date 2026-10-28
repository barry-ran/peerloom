#!/usr/bin/env python3
"""Linux 可运行的打包边界测试；绝不代替 Swift/Xcode/XCTest。"""
import importlib.util
from pathlib import Path
import plistlib
import json
import socket
import ssl
import time
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('verify', ROOT / 'scripts/verify-xcframework.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class StructureTests(unittest.TestCase):
    def make(self, root):
        canonical = root / 'canonical.h'
        canonical.write_text('test header bytes\n')
        libraries = []
        for name, platform, variant, architectures in [
            ('ios-device', 'ios', '', ['arm64']),
            ('ios-simulator', 'ios', 'simulator', ['arm64', 'x86_64']),
            ('macos', 'macos', '', ['arm64', 'x86_64'])]:
            (root / name / 'Headers').mkdir(parents=True)
            (root / name / 'Headers/device_sdk.h').write_bytes(canonical.read_bytes())
            (root / name / 'native.a').write_bytes(b'unit-fixture-not-a-real-archive')
            libraries.append(dict(LibraryIdentifier=name, LibraryPath='native.a', HeadersPath='Headers',
                SupportedPlatform=platform, SupportedPlatformVariant=variant, SupportedArchitectures=architectures))
        (root / 'Info.plist').write_bytes(plistlib.dumps({'AvailableLibraries': libraries}))
        return canonical, libraries

    def test_three_platform_variants_and_identical_canonical_header(self):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path); canonical, _ = self.make(root)
            module.verify(root, canonical)

    def test_device_simulator_mix_rejected(self):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path); canonical, values = self.make(root)
            values[0]['SupportedArchitectures'].append('x86_64')
            (root / 'Info.plist').write_bytes(plistlib.dumps({'AvailableLibraries': values}))
            with self.assertRaises(ValueError): module.verify(root, canonical)

    def test_duplicate_variant_and_escape_rejected(self):
        for field, value in [('SupportedPlatformVariant', ''), ('LibraryPath', '../outside')]:
            with tempfile.TemporaryDirectory() as path:
                root = Path(path); canonical, values = self.make(root)
                values[1][field] = value
                (root / 'Info.plist').write_bytes(plistlib.dumps({'AvailableLibraries': values}))
                with self.assertRaises(ValueError): module.verify(root, canonical)

    def test_header_drift_rejected(self):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path); canonical, _ = self.make(root)
            (root / 'macos/Headers/device_sdk.h').write_text('drift')
            with self.assertRaises(ValueError): module.verify(root, canonical)

    def test_tls_fixture_reports_actual_rejected_handshake(self):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path)
            process = subprocess.Popen(['python3', str(ROOT / 'scripts/tls-fixture.py'), path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 10
                while not (root / 'state.json').exists() and time.monotonic() < deadline:
                    self.assertIsNone(process.poll()); time.sleep(0.02)
                state = json.loads((root / 'state.json').read_text())
                port = int(state['origin'].split(':')[-1].rstrip('/'))
                with socket.create_connection(('127.0.0.1', port), timeout=4) as raw:
                    with self.assertRaises(ssl.SSLCertVerificationError):
                        ssl.create_default_context().wrap_socket(raw, server_hostname='127.0.0.1')
                while time.monotonic() < deadline:
                    state = json.loads((root / 'state.json').read_text())
                    if state['rejected_handshakes'] == 1: break
                    time.sleep(0.02)
                self.assertEqual(state['rejected_handshakes'], 1)
                self.assertEqual(state['accepted_handshakes'], 0)
            finally:
                process.terminate(); process.wait(timeout=6)

    def test_scripts_parse_and_never_fake_apple_build_on_linux(self):
        for script in (ROOT / 'scripts').glob('*.sh'):
            subprocess.run(['bash', '-n', str(script)], check=True)
            if subprocess.check_output(['uname', '-s'], text=True).strip() != 'Darwin':
                result = subprocess.run(['bash', str(script)], capture_output=True)
                self.assertEqual(result.returncode, 2)

if __name__ == '__main__': unittest.main()
