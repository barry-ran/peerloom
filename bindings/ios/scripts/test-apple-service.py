#!/usr/bin/env python3
# MIT — Copyright (c) 2026 Peerloom contributors.
"""Apple real-service fixture safety contracts; not Swift/native execution evidence."""
import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('apple_service', HERE / 'apple-service.py')
SERVICE = importlib.util.module_from_spec(spec); spec.loader.exec_module(SERVICE)
spec = importlib.util.spec_from_file_location('signing', HERE / 'inspect-test-signing.py')
SIGNING = importlib.util.module_from_spec(spec); spec.loader.exec_module(SIGNING)

class ServiceSafety(unittest.TestCase):
    def test_command_errors_retain_exit_classification_not_secrets(self):
        secret = 'synthetic-do-not-log-token'
        with self.assertRaises(SERVICE.Failure) as error:
            SERVICE.run([sys.executable, '-c', "import sys;sys.stderr.write('" + secret + "');sys.exit(7)"])
        self.assertIn('exit 7', str(error.exception))
        self.assertNotIn(secret, str(error.exception))
        with self.assertRaisesRegex(SERVICE.Failure, 'timeout'):
            SERVICE.run([sys.executable, '-c', 'import time;time.sleep(30)'], timeout=0.1)

    def test_private_files_never_replace_or_follow_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'secret'
            SERVICE.private(path, 'synthetic')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError): SERVICE.private(path, 'other')
            (root / 'link').symlink_to(path)
            with self.assertRaises(FileExistsError): SERVICE.private(root / 'link', 'other')
            self.assertEqual(path.read_text(), 'synthetic')

    def test_download_uses_truthful_identity_and_still_verifies_pinned_bytes(self):
        payload = b'synthetic pinned official archive'
        url = 'https://download.redis.io/releases/redis-8.10.3.tar.gz'
        spec = {'url': url, 'sha256': hashlib.sha256(payload).hexdigest()}
        def response(request, timeout):
            self.assertEqual(request.full_url, url)
            self.assertEqual(request.get_header('User-agent'), SERVICE.DOWNLOAD_USER_AGENT)
            self.assertIsNone(request.get_header('Authorization'))
            self.assertEqual(timeout, 30)
            result = io.BytesIO(payload)
            result.url = url
            return result
        with tempfile.TemporaryDirectory() as temporary, patch.object(SERVICE.urllib.request, 'build_opener') as factory:
            factory.return_value.open.side_effect = response
            path = Path(temporary) / 'archive'
            SERVICE.download(spec, path)
            self.assertEqual(path.read_bytes(), payload)
            with self.assertRaisesRegex(SERVICE.Failure, 'checksum mismatch'):
                SERVICE.download({**spec, 'sha256': '0' * 64}, Path(temporary) / 'mismatch')

    def test_download_http_error_discloses_status_only(self):
        secret = 'synthetic-private-query-header-body'
        error = SERVICE.urllib.error.HTTPError('https://download.redis.io/?' + secret, 403,
                                               secret, {'X-Private': secret}, io.BytesIO(secret.encode()))
        with tempfile.TemporaryDirectory() as temporary, patch.object(SERVICE.urllib.request, 'build_opener') as factory:
            factory.return_value.open.side_effect = error
            with self.assertRaises(SERVICE.Failure) as raised:
                SERVICE.download({'url': 'https://download.redis.io/releases/redis-8.10.3.tar.gz',
                                  'sha256': '0' * 64}, Path(temporary) / 'archive')
            self.assertEqual(str(raised.exception), 'dependency HTTP status 403')
            self.assertNotIn(secret, str(raised.exception))
            self.assertFalse((Path(temporary) / 'archive').exists())

    def test_tar_rejects_traversal_and_links_preserves_release_timestamps(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, name in enumerate(('../outside', '/absolute', 'root/symlink')):
                archive = root / ('bad' + str(index))
                with tarfile.open(archive, 'w') as stream:
                    item = tarfile.TarInfo(name)
                    if 'symlink' in name: item.type = tarfile.SYMTYPE; item.linkname = '/outside'
                    stream.addfile(item, io.BytesIO())
                with self.assertRaises(SERVICE.Failure): SERVICE.unpack(archive, root / ('unpack' + str(index)))
            archive = root / 'good'
            with tarfile.open(archive, 'w') as stream:
                item = tarfile.TarInfo('release/generated.c'); item.size = 1; item.mtime = 1234567890
                stream.addfile(item, io.BytesIO(b'x'))
            source = SERVICE.unpack(archive, root / 'good-out')
            self.assertEqual((source / 'generated.c').stat().st_mtime, 1234567890)

    def test_cache_links_must_resolve_inside_owned_prefix(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); prefix = root / 'cache'; prefix.mkdir()
            (prefix / 'real').write_text('binary')
            (prefix / 'alias').symlink_to('real')
            self.assertEqual(SERVICE.file_hashes(prefix)['alias'], {'symlink': 'real'})
            (prefix / 'escape').symlink_to('../outside')
            (root / 'outside').write_text('no')
            with self.assertRaises(SERVICE.Failure): SERVICE.file_hashes(prefix)

    def test_exact_preinstalled_version_is_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / 'postgres'; executable.touch()
            with patch.object(SERVICE, 'run', return_value=b'postgres (PostgreSQL) 18.6\n'):
                self.assertTrue(SERVICE.version_matches(executable, 'postgresql', '18.6'))
            with patch.object(SERVICE, 'run', return_value=b'postgres (PostgreSQL) 18.5\n'):
                self.assertFalse(SERVICE.version_matches(executable, 'postgresql', '18.6'))

    def test_three_registered_devices_and_unregistered_fourth_app_fixture(self):
        calls = []
        class Client:
            def request(self, method, path, expected, credential=None, body=None, key=None):
                calls.append((method, path, expected, credential, body))
                if path == '/v1/applications': return {'id': 'app-' + str(len(calls))}
                if path == '/v1/registration-grants': return {'grant': 'synthetic'}
                if path == '/v1/device-registrations': return {'device_id': 'device-' + str(len(calls)), 'device_credential': 'synthetic', 'expires_at': 'synthetic'}
                return {'id': 'grant'}
        devices = SERVICE.fixture(Client(), 'synthetic-admin')
        self.assertEqual(len({value['application_id'] for value in devices.values()}), 4)
        first = devices['first_registration']
        self.assertEqual(set(first), {'application_id', 'registration_grant', 'installation_public_key', 'idempotency_key'})
        self.assertTrue(first['registration_grant'])
        self.assertTrue(first['installation_public_key'])
        self.assertTrue(first['idempotency_key'])
        self.assertNotIn('synthetic-admin', json.dumps(devices))
        first_app = [body for _, path, _, _, body in calls if path == '/v1/applications'][-1]
        self.assertEqual(first_app['registration_mode'], 'grant')
        first_grant = [body for _, path, _, _, body in calls if path == '/v1/registration-grants'][-1]
        self.assertEqual(first_grant, {'application_id': first['application_id'], 'expires_in_seconds': 1200})
        registration = [body for _, path, _, _, body in calls if path == '/v1/device-registrations']
        self.assertEqual(len(registration), 3)
        self.assertTrue(all(body['platform'] == 'ios' for body in registration))
        self.assertNotIn(first['application_id'], {body['application_id'] for body in registration})
        grants = [body for _, path, _, _, body in calls if path == '/v1/connection-grants']
        self.assertEqual(len(grants), 2)
        self.assertTrue(all(body['source_device_id'] == devices['source']['device_id'] for body in grants))
        self.assertEqual({body['target_device_id'] for body in grants}, {devices['target']['device_id'], devices['third']['device_id']})

    def test_service_scheme_is_separate_and_original_suite_retained(self):
        project = HERE.parent / 'SimulatorHost/PeerloomSimulatorHost.xcodeproj'
        old = ET.parse(project / 'xcshareddata/xcschemes/PeerloomSimulatorHost.xcscheme')
        new = ET.parse(project / 'xcshareddata/xcschemes/PeerloomSwiftService.xcscheme')
        self.assertEqual(old.find('.//TestableReference/BuildableReference').attrib['BlueprintIdentifier'], 'A00000000000000000000011')
        self.assertEqual(new.find('.//TestableReference/BuildableReference').attrib['BlueprintIdentifier'], 'A00000000000000000000060')
        self.assertEqual(new.find('.//TestableReference').attrib['skipped'], 'NO')
        source = (HERE.parent / 'ServiceTests/SwiftServiceTests.swift').read_text()
        self.assertNotIn('MockNative', source.replace('// Neither an injected memory store nor MockNative is used in this suite.', ''))
        self.assertIn('PeerloomSDK.open(configuration: config)', source)
        self.assertIn('KeychainIdentityStore()', source)
        self.assertIn('empty.revision == 0, empty.identity == nil', source)
        self.assertIn('firstSDK.start(registration: PeerloomRegistration(', source)
        self.assertIn('idempotencyKey: first.idempotency_key', source)
        self.assertIn('saved.identity?.deviceID == registeredID', source)
        self.assertIn('reopenedSDK.start() == registeredID', source)
        self.assertLess(source.index('try await firstSDK.close()'), source.index('let reopenedSDK'))
        self.assertNotIn('operation: .save', source[source.index('let first ='):source.index('for (index, device)')])
        self.assertIn('256 * 1024', source)
        self.assertIn('finishWrite()', source)
        self.assertIn('mode: .lowLatencyMessage', source)

    def test_signing_requires_exact_service_bundle_and_expanded_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); products = root / 'Build/Products'; products.mkdir(parents=True)
            developer = root / 'Developer'; developer.mkdir()
            app = products / 'Debug/PeerloomSimulatorHost.app'; app.mkdir(parents=True)
            (app / 'PeerloomSimulatorHost').write_bytes(b'fixture')
            test = app / 'PlugIns/PeerloomServiceTests.xctest'; test.mkdir(parents=True)
            (products / 'service.xctestrun').write_bytes(plistlib.dumps({'Target': {'TestHostPath': '__TESTROOT__/Debug/PeerloomSimulatorHost.app', 'TestBundlePath': '__TESTHOST__/PlugIns/PeerloomServiceTests.xctest'}}))
            xcent = root / 'Build/Intermediates.noindex/Host'; xcent.mkdir(parents=True)
            (xcent / 'PeerloomSimulatorHost.app-Simulated.xcent').write_bytes(plistlib.dumps({'keychain-access-groups': ['FAKETEAMID.io.peerloom.validation.simulatorhost']}))
            with patch.object(SIGNING.subprocess, 'run', return_value=types.SimpleNamespace(returncode=0, stdout='', stderr='')), patch('sys.stdout', new=io.StringIO()):
                SIGNING.inspect(products, developer, True, 'PeerloomServiceTests.xctest')
                with self.assertRaises(ValueError): SIGNING.inspect(products, developer, True)
                with self.assertRaises(ValueError): SIGNING.inspect(products, developer, True, '../arbitrary')

    def test_cleanup_continues_after_one_resource_failure(self):
        calls = []
        class Log:
            def close(self): calls.append('log')
        def stop(process):
            calls.append(process)
            if process == 'second': raise OSError('synthetic private detail')
        with patch.object(SERVICE.signal, 'signal'), patch.object(SERVICE, 'run', side_effect=SERVICE.Failure('timeout')), patch.object(SERVICE, 'stop', side_effect=stop):
            failures = SERVICE.cleanup_owned('owned-id', ['first', 'second'], [Log()])
        self.assertEqual(calls, ['second', 'first', 'log'])
        self.assertEqual(failures, ['owned-simulator', 'owned-process'])

    def test_first_interruption_disables_repeated_signals_before_raising(self):
        with patch.object(SERVICE.signal, 'signal') as signal:
            with self.assertRaises(SERVICE.Failure): SERVICE.interrupted(15, None)
            self.assertEqual(signal.call_args_list, [unittest.mock.call(SERVICE.signal.SIGTERM, SERVICE.signal.SIG_IGN), unittest.mock.call(SERVICE.signal.SIGINT, SERVICE.signal.SIG_IGN)])

    def test_simulator_id_preserves_source_case(self):
        identifier = 'E3662E63-E85F-4982-B0F4-79F2E786CA4F'
        self.assertEqual(SERVICE.validate_device_id(identifier + '\n'), identifier)
        for wrong in ('', '../bad', identifier + '\nother'):
            with self.assertRaises((ValueError, SERVICE.Failure)): SERVICE.validate_device_id(wrong)

if __name__ == '__main__': unittest.main()
