#!/usr/bin/env python3
"""Linux 可运行的打包边界测试；绝不代替 Swift/Xcode/XCTest。"""
import importlib.util
import contextlib
import io
from pathlib import Path
import plistlib
import json
import socket
import ssl
import time
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('verify', ROOT / 'scripts/verify-xcframework.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
package_spec = importlib.util.spec_from_file_location('package_resolution', ROOT / 'scripts/verify-package-resolution.py')
package_module = importlib.util.module_from_spec(package_spec)
package_spec.loader.exec_module(package_module)

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

    def test_manifest_anchor_and_native_resolution_gate_are_present(self):
        manifest = (ROOT / 'Package.swift').read_text()
        self.assertIn('URL(fileURLWithPath: #filePath).deletingLastPathComponent()', manifest)
        self.assertIn('packageRoot.appendingPathComponent("Artifacts/CPeerloom.xcframework").path', manifest)
        self.assertIn('.binaryTarget(name: "CPeerloom", path: "Artifacts/CPeerloom.xcframework")', manifest)
        self.assertIn('run macos-package-resolution 180 python3 "$HERE/scripts/verify-package-resolution.py"',
                      (ROOT / 'scripts/test-native.sh').read_text())

    def test_resolution_checker_requires_all_four_actual_package_parses(self):
        # Mock only the Swift process here; actual native CI uses the real built XCFramework.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); built = root / 'built'; source = root / 'source'
            (built / 'Artifacts/CPeerloom.xcframework').mkdir(parents=True); source.mkdir()
            for package in (built, source): (package / 'Package.swift').write_text('synthetic manifest')
            calls = []
            def parse(command, **kwargs):
                package = Path(command[3]); calls.append((package, kwargs['cwd']))
                self.assertEqual(command[:3], ['swift', 'package', '--package-path'])
                self.assertEqual(command[4], 'dump-package')
                self.assertEqual(kwargs['timeout'], 35)
                kind = 'binary' if package == built.resolve() else 'system'
                value = {'targets': [{'name': 'CPeerloom', 'type': kind, 'path': 'Artifacts/CPeerloom.xcframework'}]}
                return subprocess.CompletedProcess(command, 0, json.dumps(value).encode(), b'')
            with mock.patch.object(package_module.subprocess, 'run', side_effect=parse), contextlib.redirect_stdout(io.StringIO()):
                package_module.verify(built, source)
            self.assertEqual(len(calls), 4)
            self.assertEqual(calls[0], (built.resolve(), built.resolve()))
            self.assertEqual(calls[2], (source.resolve(), source.resolve()))
            self.assertNotIn(calls[1][1], (built.resolve(), source.resolve()))
            self.assertEqual(calls[1][1], calls[3][1])
            wrong = subprocess.CompletedProcess([], 0, b'{"targets":[{"name":"CPeerloom","type":"system"}]}', b'')
            with mock.patch.object(package_module.subprocess, 'run', return_value=wrong):
                with self.assertRaisesRegex(ValueError, 'target kind'): package_module.verify(built, source)
            with mock.patch.object(package_module.subprocess, 'run', side_effect=subprocess.TimeoutExpired('swift', 35)):
                with self.assertRaises(subprocess.TimeoutExpired): package_module.verify(built, source)

    def test_scripts_parse_and_never_fake_apple_build_on_linux(self):
        for script in (ROOT / 'scripts').glob('*.sh'):
            subprocess.run(['bash', '-n', str(script)], check=True)
            if subprocess.check_output(['uname', '-s'], text=True).strip() != 'Darwin':
                result = subprocess.run(['bash', str(script)], capture_output=True)
                self.assertEqual(result.returncode, 2)

if __name__ == '__main__': unittest.main()
