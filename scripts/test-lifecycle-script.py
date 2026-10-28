#!/usr/bin/env python3
"""生命周期 CI 安全编排回归；不代替真实 C/UDP/数据库测试。"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('lifecycle_fixture', HERE / 'prepare-lifecycle-fixture.py')
fixture_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture_module)

MOCK = r'''import json, os, pathlib, stat, sys
name = pathlib.Path(sys.argv[0]).name
root = pathlib.Path.cwd()
if name == 'cargo':
    p = pathlib.Path(os.environ['TEST_MULTICONNECTION_FIXTURE_FILE'])
    assert p.exists() and stat.S_IMODE(p.stat().st_mode) == 0o600
    stage = 'channels' if 'sdk_channels' in sys.argv else 'multiconnection'
    if stage == 'multiconnection':
        assert os.environ['TEST_LEASE_ADMIN_FIXTURE'] == 'admin'
    else:
        assert not (p.parent / 'multiconnection.json').exists()
    assert '--ignored' in sys.argv
    (root / (stage + '-ran')).touch()
    sys.exit(7 if os.environ['FAIL'] == stage else 0)
if name == 'python3' and 'prepare-multiconnection-fixture.py' in sys.argv[1]:
    output = pathlib.Path(sys.argv[sys.argv.index('--output') + 1])
    assert not output.exists() and not (output.parent / 'recovery.json').exists()
    output.write_text('{}')
    output.chmod(0o600)
    stage = ('ffi-channels' if output.name == 'ffi-channels.json' else
             'channels' if output.name == 'channels.json' else 'multiconnection')
    if stage == 'ffi-channels':
        assert not (output.parent / 'channels.json').exists()
    sys.exit(7 if os.environ['FAIL'] == stage + '-prepare' else 0)
if name == 'python3' and 'prepare-lifecycle-fixture.py' in sys.argv[1]:
    output = pathlib.Path(sys.argv[sys.argv.index('--pair-output') + 1])
    assert not output.exists()
    assert stat.S_IMODE(output.parent.stat().st_mode) == 0o700
    direct = '--direct-reset' in sys.argv
    if not direct:
        assert not list(output.parent.glob('reset-*.json'))
    output.write_text(json.dumps({'direct_reset_enabled': direct, 'secret': 'never-log-this-secret'}))
    output.chmod(0o600)
    (root / 'owned-directory').write_text(str(output.parent))
    sys.exit(7 if os.environ['FAIL'] == 'prepare' else 0)
if name == 'python3' and 'run-channels.py' in sys.argv[1]:
    p = pathlib.Path(os.environ['TEST_MULTICONNECTION_FIXTURE_FILE'])
    assert p.exists() and p.name == 'ffi-channels.json'
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert not (p.parent / 'channels.json').exists()
    (root / 'ffi-channels-ran').touch()
    sys.exit(7 if os.environ['FAIL'] == 'ffi-channels' else 0)
if name == 'python3':
    p = pathlib.Path(os.environ['TEST_SIGNAL_FIXTURE_FILE'])
    assert json.loads(p.read_text())['direct_reset_enabled'] is True
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    (root / 'c-ran').touch()
    counter = root / 'c-count'
    count = int(counter.read_text()) + 1 if counter.exists() else 1
    counter.write_text(str(count))
    assert p.name == 'reset-' + str(count) + '.json'
    fail = os.environ['FAIL'] == 'c' or (os.environ['FAIL'] == 'c-round2' and count == 2)
    sys.exit(7 if fail else 0)
assert '--recovery' in sys.argv
p = pathlib.Path(sys.argv[sys.argv.index('--pair-fixture') + 1])
assert json.loads(p.read_text())['direct_reset_enabled'] is False
assert not list(p.parent.glob('reset-*.json'))
(root / 'recovery-ran').touch()
sys.exit(7 if os.environ['FAIL'] == 'recovery' else 0)
'''


class LifecycleScriptTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix', 'POSIX executable mode checked on Unix CI')
    def test_repository_entrypoint_is_executable(self):
        self.assertTrue((HERE / 'test-lifecycle.sh').stat().st_mode & stat.S_IXUSR)

    def run_shell(self, failure):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'scripts').mkdir()
            (root / 'bin').mkdir()
            shutil.copyfile(HERE / 'test-lifecycle.sh', root / 'scripts/test-lifecycle.sh')
            for relative in ['bin/python3', 'bin/cargo', 'scripts/test-managed-relay.sh']:
                p = root / relative
                p.write_text('#!' + sys.executable + '\n' + MOCK)
                p.chmod(0o700)
            env = dict(os.environ, PATH=str(root / 'bin') + os.pathsep + os.environ['PATH'], FAIL=failure)
            result = subprocess.run(['bash', '-x', str(root / 'scripts/test-lifecycle.sh'),
                                     '--base-url', 'http://127.0.0.1:18080', '--admin-fixture', 'admin',
                                     '--shared-secret-file', 'secret'], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 7 if failure else 0, result.stderr)
            self.assertFalse(Path((root / 'owned-directory').read_text()).exists())
            self.assertNotIn('never-log-this-secret', result.stdout + result.stderr)
            if failure == 'c-round2':
                self.assertEqual((root / 'c-count').read_text(), '2')
                self.assertFalse((root / 'recovery-ran').exists())
            if not failure:
                self.assertTrue((root / 'c-ran').exists())
                self.assertEqual((root / 'c-count').read_text(), '3')
                self.assertTrue((root / 'recovery-ran').exists())
                self.assertTrue((root / 'multiconnection-ran').exists())
                self.assertTrue((root / 'channels-ran').exists())
                self.assertTrue((root / 'ffi-channels-ran').exists())

    def test_success_uses_distinct_private_pairs(self):
        self.run_shell('')
    def test_prepare_failure_cleanup(self):
        self.run_shell('prepare')
    def test_second_c_round_failure_stops_without_retry_or_later_stages(self):
        self.run_shell('c-round2')

    def test_c_failure_cleanup_and_no_recovery(self):
        self.run_shell('c')
    def test_recovery_failure_cleanup(self):
        self.run_shell('recovery')

    def test_multiconnection_prepare_failure_cleanup(self):
        self.run_shell('multiconnection-prepare')

    def test_multiconnection_failure_cleanup(self):
        self.run_shell('multiconnection')

    def test_channels_prepare_failure_cleanup(self):
        self.run_shell('channels-prepare')

    def test_channels_failure_cleanup(self):
        self.run_shell('channels')

    def test_ffi_channels_prepare_failure_cleanup(self):
        self.run_shell('ffi-channels-prepare')

    def test_ffi_channels_failure_cleanup(self):
        self.run_shell('ffi-channels')

    def test_direct_mode_is_explicit_http_patch(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'pair.json'
            pair = {'source': {'application_id': '11111111-1111-4111-8111-111111111111'}, 'target': {}}
            with patch.object(fixture_module.management, 'Client') as client, \
                    patch.object(fixture_module.management, 'read_fixture', return_value='private'), \
                    patch.object(fixture_module.management, 'exercise', return_value=pair):
                client.return_value.request.return_value = {'application': {'registration_mode': 'direct'}}
                fixture_module.prepare('http://127.0.0.1', 'admin', output, True)
                args = client.return_value.request.call_args.args
                self.assertEqual(args[:3], ('PATCH', '/v1/applications/11111111-1111-4111-8111-111111111111', 200))
                self.assertEqual(args[4], {'registration_mode': 'direct'})
                self.assertTrue(json.loads(output.read_text())['direct_reset_enabled'])
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_existing_output_rejected_before_network(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'pair.json'
            output.write_text('preserve')
            with patch.object(fixture_module.management, 'Client') as client:
                with self.assertRaises(fixture_module.management.CheckFailure):
                    fixture_module.prepare('http://127.0.0.1', 'admin', output)
                client.assert_not_called()
            self.assertEqual(output.read_text(), 'preserve')

    def test_nonloopback_rejected(self):
        with self.assertRaises(fixture_module.management.CheckFailure):
            fixture_module.prepare('http://192.0.2.1', 'absent', '/tmp/not-created-peerloom-fixture')


if __name__ == '__main__':
    unittest.main()
