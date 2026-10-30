#!/usr/bin/env python3
"""发布编译入口离线安全回归：只mock，不运行编译器或访问网络。"""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('build_release', ROOT / 'scripts/build-release-only.py')
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)
SHA = '1' * 40
REQUEST = {'format_version': 1, 'version': '0.1.4', 'tested_sha': '2' * 40, 'retained_sha': '3' * 40, 'revision': 2}
ENV = {'GITHUB_EVENT_NAME': 'push', 'GITHUB_REPOSITORY': B.REPO,
       'GITHUB_REF': 'refs/heads/master', 'GITHUB_SHA': SHA}
EVENT = {'repository': {'full_name': B.REPO}, 'ref': 'refs/heads/master',
         'before': '4' * 40, 'after': SHA, 'created': False, 'deleted': False, 'forced': False}


class BuildRequest(unittest.TestCase):
    def check(self, request=None, version='0.1.4', env=None, event=None, head=SHA):
        B.validate_context(REQUEST if request is None else request, version,
                           ENV if env is None else env, EVENT if event is None else event, head)

    def test_exact_request(self):
        self.check()

    def test_unknown_field_or_shell_payload_rejected(self):
        for field in ('ref', 'command', 'platform', 'token'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check(request=dict(REQUEST, **{field: 'echo untrusted'}))
        for key in REQUEST:
            value = dict(REQUEST)
            del value[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                self.check(request=value)

    def test_request_types_and_versions(self):
        for value in (False, True, 2, '1', None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.check(request=dict(REQUEST, format_version=value))
        for version in ('0.1.3', 'v0.1.4', '0.1.4;echo', '', None):
            with self.subTest(version=version), self.assertRaises(ValueError):
                self.check(version=version)
        for key in ('tested_sha', 'retained_sha'):
            for value in ('main', 'a' * 39, 'a' * 41, 'A' * 40, None, 123):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    self.check(request=dict(REQUEST, **{key: value}))

    def test_revision_is_positive_integer(self):
        for revision in (None, True, False, 0, -1, '2', 2.0):
            with self.subTest(revision=revision), self.assertRaises(ValueError):
                self.check(request=dict(REQUEST, revision=revision))

    def test_only_real_master_push(self):
        for key, value in (('GITHUB_EVENT_NAME', 'pull_request'), ('GITHUB_EVENT_NAME', 'workflow_dispatch'),
                           ('GITHUB_REPOSITORY', 'other/peerloom'), ('GITHUB_REF', 'refs/heads/feat/release'),
                           ('GITHUB_REF', 'refs/tags/v0.1.4'), ('GITHUB_SHA', '5' * 40),
                           ('PEERLOOM_CARGO_FEATURES', 'other'), ('CARGO_TARGET_DIR', '/tmp/reused')):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.check(env=dict(ENV, **{key: value}))
        for key, value in (('created', True), ('deleted', True), ('forced', True),
                           ('ref', 'refs/heads/other'), ('after', '5' * 40),
                           ('before', SHA), ('before', '0' * 40), ('before', ''),
                           ('repository', {'full_name': 'other/peerloom'})):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.check(event=dict(EVENT, **{key: value}))
        with self.assertRaises(ValueError):
            self.check(head='main')

    def test_linux_only_compiles_links_packages(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'src/device-sdk/target/release').mkdir(parents=True)
            (root / 'src/device-sdk/device-ffi/include').mkdir(parents=True)
            (root / 'LICENSE').write_text('MIT')
            (root / 'src/device-sdk/device-ffi/include/device_sdk.h').write_text('header')
            for name in ('libdevice_ffi.so', 'libdevice_ffi.a'):
                (root / 'src/device-sdk/target/release' / name).write_bytes(b'fixture')
            with patch.object(B, 'ROOT', root), patch.object(B.platform, 'system', return_value='Linux'), \
                 patch.object(B.platform, 'machine', return_value='x86_64'), patch.object(B, 'run') as run:
                B.linux()
            commands = [[str(arg) for arg in item.args[0]] for item in run.call_args_list]
            self.assertEqual(sum(command[:2] == ['go', 'build'] for command in commands), 5)
            self.assertEqual(sum(command[0] == 'cc' for command in commands), 2)
            self.assertTrue(any('--locked' in c and '--release' in c for c in commands))
            self.assertFalse(any('test' in c or 'docker' in c or c[0].endswith('header-shared') or
                                 c[0].endswith('header-static') for c in commands))
            self.assertEqual([c[c.index('--platform') + 1] for c in commands if '--platform' in c],
                             ['linux-x86_64', 'server-linux-amd64'])

    def test_windows_links_compiler_declared_libraries_without_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(B, 'ROOT', Path(directory)), patch.object(B.platform, 'system', return_value='Windows'), \
                 patch.object(B.platform, 'machine', return_value='AMD64'), patch.object(B, 'run') as run:
                run.return_value.stdout = ''
                run.return_value.stderr = 'note: native-static-libs: legacy_stdio_definitions.lib iphlpapi.lib kernel32.lib bcrypt.lib advapi32.lib kernel32.lib ntdll.lib userenv.lib ws2_32.lib dbghelp.lib /defaultlib:msvcrt\n'
                B.windows()
            commands = [[str(arg) for arg in item.args[0]] for item in run.call_args_list]
            links = [c for c in commands if c[0] == 'cl.exe']
            self.assertEqual(len(links), 2)
            self.assertIn('bcrypt.lib', links[1])
            self.assertIn('/defaultlib:msvcrt', links[1])
            self.assertGreater(links[1].index('/defaultlib:msvcrt'), links[1].index('/link'))
            self.assertGreater(links[1].index('bcrypt.lib'), links[1].index('/link'))
            self.assertFalse(any(c[0].endswith('header-static.exe') or 'test' in c for c in commands))

    def test_windows_rejects_unknown_static_link_flags(self):
        for output in ('', 'note: native-static-libs: /OUT:bad.exe\n',
                       'note: native-static-libs: /defaultlib:other\n',
                       'note: native-static-libs: @response.lib\n',
                       'note: native-static-libs: C:/unsafe.lib\n',
                       'note: native-static-libs: a.lib\nnote: native-static-libs: b.lib\n'):
            with tempfile.TemporaryDirectory() as directory:
                with patch.object(B, 'ROOT', Path(directory)), patch.object(B.platform, 'system', return_value='Windows'), \
                     patch.object(B.platform, 'machine', return_value='AMD64'), patch.object(B, 'run') as run:
                    run.return_value.stdout, run.return_value.stderr = '', output
                    with self.assertRaises(ValueError):
                        B.windows()


class Workflow(unittest.TestCase):
    def setUp(self):
        self.value = yaml.load((ROOT / '.github/workflows/release-build.yml').read_text(encoding='utf-8'), Loader=yaml.BaseLoader)

    def test_exact_trigger_permissions_and_jobs(self):
        self.assertEqual(self.value['on'], {'push': {'branches': ['master'], 'paths': ['release/build-request.json']}})
        self.assertEqual(self.value['permissions'], {'contents': 'read'})
        self.assertEqual(self.value['concurrency']['cancel-in-progress'], 'false')
        self.assertEqual(set(self.value['jobs']), {'linux-release', 'windows-release', 'apple-release', 'android-release'})
        for job in self.value['jobs'].values():
            self.assertEqual(job['if'], "github.repository == 'barry-ran/peerloom' && github.event_name == 'push' && github.ref == 'refs/heads/master'")
            self.assertNotIn('permissions', job)
            self.assertNotIn('strategy', job)
            checkout = job['steps'][0]
            self.assertEqual(checkout, {'uses': 'actions/checkout@11d5960a326750d5838078e36cf38b85af677262',
                                       'with': {'ref': '${{ github.sha }}', 'persist-credentials': 'false'}})

    def test_pinned_actions_no_functional_run_or_secrets(self):
        actions = {'actions/checkout@11d5960a326750d5838078e36cf38b85af677262',
                   'actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff',
                   'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02'}
        for job in self.value['jobs'].values():
            for step in job['steps']:
                self.assertNotIn('if', step)
                self.assertNotIn('continue-on-error', step)
                if 'uses' in step:
                    self.assertIn(step['uses'], actions)
                command = step.get('run', '')
                for forbidden in ('cargo test', 'go test', 'swift test', 'test-native.sh', 'test-compose.sh',
                                  'test-windows.ps1', 'run-capacity', 'simctl', 'system-images;',
                                  'assembleDebugAndroidTest', ':sample:', 'secrets.', 'GH_TOKEN', 'gh release'):
                    self.assertNotIn(forbidden, command)
        apple = '\n'.join(s.get('run', '') for s in self.value['jobs']['apple-release']['steps'])
        self.assertIn('build-xcframework.sh', apple)
        self.assertIn('swift build', apple)
        android = '\n'.join(s.get('run', '') for s in self.value['jobs']['android-release']['steps'])
        self.assertIn(':library:assembleRelease', android)
        self.assertIn('--offline :library:collectMavenEvidence', android)
        self.assertIn('verify-artifacts.py dist/android/library-release.aar', android)

    def test_five_exact_artifacts(self):
        found = {}
        for job in self.value['jobs'].values():
            for step in job['steps']:
                if step.get('uses', '').startswith('actions/upload-artifact@'):
                    config = step['with']
                    self.assertEqual(config['if-no-files-found'], 'error')
                    self.assertEqual(config['retention-days'], '14')
                    self.assertNotIn(config['name'], found)
                    found[config['name']] = config['path']
        expected = {'linux': 'linux-x86_64', 'server-linux-amd64': 'server-linux-amd64',
                    'windows': 'windows-x86_64', 'apple': 'apple', 'android': 'android'}
        self.assertEqual(found, {'peerloom-' + name + '-release-${{ github.sha }}': 'dist/release/' + platform + '/'
                                 for name, platform in expected.items()})


if __name__ == '__main__':
    unittest.main()
