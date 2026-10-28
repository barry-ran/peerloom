#!/usr/bin/env python3
"""Host-only negative tests; no Windows features, WSL, processes or services are changed."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock
import zipfile

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('windows_service', ROOT / 'windows-service.py')
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)


class ScopeTest(unittest.TestCase):
    def test_scope_only_current_runner_owned_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            name = 'PeerloomCI-' + 'a' * 32
            directory = base / name
            directory.mkdir()
            env = {'RUNNER_TEMP': temp, 'GITHUB_ACTIONS': 'true'}
            self.assertEqual(service.validate_scope(directory, name, env, 'win32'), directory.resolve())
            for platform, environment, path, distro in (
                ('linux', env, directory, name), ('win32', {**env, 'GITHUB_ACTIONS': 'false'}, directory, name),
                ('win32', env, base, name), ('win32', env, directory, 'Ubuntu'),
            ):
                with self.assertRaises(ValueError):
                    service.validate_scope(path, distro, environment, platform)

    @unittest.skipUnless(service.os.name == 'nt', 'requires native Windows pathname API')
    def test_windows_short_and_long_names_use_same_owned_scope(self):
        import ctypes
        from ctypes import wintypes
        short_name = ctypes.WinDLL('kernel32', use_last_error=True).GetShortPathNameW
        short_name.argtypes = (wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD)
        short_name.restype = wintypes.DWORD
        with tempfile.TemporaryDirectory() as temp:
            name = 'PeerloomCI-' + 'b' * 32
            directory = Path(temp) / name
            directory.mkdir()
            long_base = Path(temp).resolve()
            buffer = ctypes.create_unicode_buffer(32768)
            count = short_name(str(long_base), buffer, len(buffer))
            self.assertTrue(0 < count < len(buffer))
            short_base = Path(buffer.value)
            self.assertTrue(short_base.samefile(long_base))
            for supplied, configured in ((short_base, long_base), (long_base, short_base)):
                env = {'RUNNER_TEMP': str(configured), 'GITHUB_ACTIONS': 'true'}
                self.assertEqual(service.validate_scope(supplied / name, name, env, 'win32'), directory.resolve())
            print('Windows short pathname alias exercised=' + str(str(short_base).casefold() != str(long_base).casefold()))

    def test_wsl_mount_mapping_never_accepts_unc(self):
        self.assertEqual(service.wsl_mounted_path(r'D:\a\test folder\redis.archive'), '/mnt/d/a/test folder/redis.archive')
        for path in ('/tmp/test', r'\\server\share\file', 'relative'):
            with self.assertRaises(ValueError):
                service.wsl_mounted_path(path)


class ProcessTest(unittest.TestCase):
    def test_timeout_targets_only_admitted_parent_tree_before_kill(self):
        child = Mock(pid=12345)
        child.communicate.side_effect = service.subprocess.TimeoutExpired('cargo', 1)
        child.poll.return_value = None
        stopped = service.subprocess.CompletedProcess([], 0)
        with patch.object(service.subprocess, 'Popen', return_value=child), patch.object(service.subprocess, 'run', return_value=stopped) as stop, patch.object(service.sys, 'platform', 'win32'):
            with self.assertRaises(TimeoutError):
                service.run(['cargo', 'test'], timeout=1)
            self.assertEqual(stop.call_args.args[0], ['taskkill.exe', '/PID', '12345', '/T', '/F'])
            child.wait.assert_called_once_with(timeout=10)

    def test_unconfirmed_tree_cleanup_is_not_success(self):
        child = Mock(pid=12345)
        child.communicate.side_effect = service.subprocess.TimeoutExpired('cargo', 1)
        child.poll.return_value = None
        with patch.object(service.subprocess, 'Popen', return_value=child), patch.object(service.subprocess, 'run', return_value=service.subprocess.CompletedProcess([], 1)), patch.object(service.sys, 'platform', 'win32'):
            with self.assertRaisesRegex(RuntimeError, 'cleanup unconfirmed'):
                service.run(['cargo', 'test'], timeout=1)


class ManagementFixture(unittest.TestCase):
    def test_pair_uses_same_admin_and_windows_metadata(self):
        client = Mock()
        client.request.side_effect = [
            {'id': 'app-a'}, {'grant': 'reg-a'}, {'device_id': 'device-a'},
            {'id': 'app-b'}, {'grant': 'reg-b'}, {'device_id': 'device-b'}, {},
        ]
        credential = 'svc_' + 'a' * 43
        pair = service.create_authorized_pair(client, credential)
        self.assertEqual(pair['source']['application_id'], 'app-a')
        self.assertEqual(pair['target']['device_id'], 'device-b')
        self.assertEqual(client.request.call_count, 7)
        for index in (2, 5):
            self.assertEqual(client.request.call_args_list[index].kwargs['body']['platform'], 'windows')
        self.assertEqual(client.request.call_args_list[-1].args[3], credential)
        self.assertEqual(client.request.call_args_list[-1].args[4]['max_sessions'], 1)
        with self.assertRaises(ValueError):
            service.create_authorized_pair(client, 'device-not-admin')

class ArchiveTest(unittest.TestCase):
    def test_download_hash_and_host_fail_closed(self):
        class Response(io.BytesIO):
            url = 'https://download.redis.io/releases/test.tar.gz'
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / 'download'
            data = b'not executable fixture'
            good = {'url': Response.url, 'sha256': hashlib.sha256(data).hexdigest()}
            with patch.object(service.urllib.request, 'urlopen', return_value=Response(data)):
                service.download(good, destination)
            self.assertEqual(destination.read_bytes(), data)
            with self.assertRaises(ValueError):
                service.download({**good, 'url': 'https://other.example/archive'}, destination)
            with patch.object(service.urllib.request, 'urlopen', return_value=Response(data)), self.assertRaises(ValueError):
                service.download({**good, 'sha256': '0' * 64}, Path(temp) / 'tampered')
            redirected = Response(data)
            redirected.url = 'https://other.example/archive'
            with patch.object(service.urllib.request, 'urlopen', return_value=redirected), self.assertRaises(ValueError):
                service.download(good, Path(temp) / 'redirect')

    def test_zip_paths_and_links_rejected_before_extraction(self):
        for name, symlink in (('../escape', False), ('C:/escape', False), ('/escape', False), ('pgsql/link', True)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                archive = Path(temp) / 'pg.zip'
                with zipfile.ZipFile(archive, 'w') as data:
                    item = zipfile.ZipInfo(name)
                    if symlink:
                        item.external_attr = 0o120777 << 16
                    data.writestr(item, 'fixture')
                with self.assertRaises(ValueError):
                    service.extract_postgres(archive, Path(temp) / 'out')
                self.assertFalse((Path(temp) / 'out').exists())

    def test_dependency_pins_are_explicit_official_sha256(self):
        dependencies = json.loads((ROOT / 'windows-service-dependencies.json').read_text())
        self.assertEqual(dependencies['postgresql']['version'], '18.6')
        self.assertEqual(dependencies['redis']['version'], '8.10.3')
        for spec in dependencies.values():
            self.assertRegex(spec['sha256'], r'^[a-f0-9]{64}$')
            self.assertEqual(service.urllib.parse.urlparse(spec['url']).scheme, 'https')
            self.assertIn(service.urllib.parse.urlparse(spec['url']).hostname, service.HOSTS)

    def test_no_privileged_or_global_mutation_fallback(self):
        source = (ROOT / 'windows-service.py').read_text() + (ROOT / 'test-windows-service.ps1').read_text()
        for forbidden in ('--set-default', '--shutdown', '--install', 'Enable-WindowsOptionalFeature', 'Start-Service', '-Verb RunAs', 'netsh', 'Set-NetFirewall'):
            self.assertNotIn(forbidden, source)
        self.assertIn("'--version', '1'", source)
        self.assertIn("'--unregister', args.distro", source)


if __name__ == '__main__':
    unittest.main()
