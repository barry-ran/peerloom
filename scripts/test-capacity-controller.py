#!/usr/bin/env python3
# MIT — Copyright (c) 2026 Peerloom contributors.
"""容量验收控制器安全回归；不声称已完成真实 500 连接测试。"""
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('capacity', Path(__file__).with_name('test-capacity.py'))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class CapacityControllerTests(unittest.TestCase):
    def test_private_failure_retained_until_diagnosis_success_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(m.Failure):
                with m.private_workspace(root) as private:
                    m.private(private / 'sdk.log', 'synthetic diagnostic')
                    raise m.Failure('failed')
            self.assertEqual((root / 'private').stat().st_mode & 0o777, 0o700)
            self.assertEqual((root / 'private/sdk.log').stat().st_mode & 0o777, 0o600)
            self.assertTrue((root / 'private/sdk.log').exists())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with m.private_workspace(root) as private:
                m.private(private / 'sdk.log', 'synthetic')
            self.assertFalse((root / 'private').exists())

    def test_secret_output_is_exclusive_private(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture'
            m.private(path, 'synthetic')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                m.private(path, 'changed')
            self.assertEqual(path.read_text(), 'synthetic')
            link = Path(directory) / 'link'; link.symlink_to(path)
            with self.assertRaises(OSError):
                m.private(link, 'changed')

    def test_only_grants_provisioned_no_device_database_shortcut(self):
        class Client:
            def __init__(self): self.calls = []
            def request(self, method, route, status, credential, body, key):
                self.calls.append((method, route, body))
                return {'id': str(len(self.calls)), 'max_connections': -1, 'grant': 'reg_synthetic'}
        client = Client()
        value = m.create_fixture(client, 'svc_synthetic', 500, Path('/private/owned'), 'http://127.0.0.1:1234/')
        self.assertEqual(len(value['registrations']), 501)
        self.assertEqual(len(client.calls), 503)
        self.assertEqual({call[1] for call in client.calls}, {'/v1/applications', '/v1/registration-grants'})
        self.assertEqual(value['hold_seconds'], 120)
        self.assertNotIn('device_credential', json.dumps(value))
        self.assertNotEqual(value['registrations'][0]['application_id'], value['registrations'][1]['application_id'])

    def test_command_error_reports_status_not_secret_stderr(self):
        with self.assertRaises(m.Failure) as result:
            m.run([sys.executable, '-c', 'import sys; print("synthetic-private-token",file=sys.stderr);sys.exit(17)'])
        self.assertIn('exit 17', str(result.exception))
        self.assertNotIn('synthetic', str(result.exception))

    def test_timeout_reaps_own_group(self):
        with self.assertRaises(m.Failure) as result:
            m.run([sys.executable, '-c', 'import time;time.sleep(30)'], timeout=.1)
        self.assertIn('timeout', str(result.exception))

    def test_cleanup_failure_still_attempts_all_children_and_logs(self):
        first, second = mock.Mock(), mock.Mock()
        streams = [io.StringIO(), io.StringIO()]
        with mock.patch.object(m.signal, 'signal'), mock.patch.object(m, 'stop', side_effect=[OSError(), None]) as stop:
            with self.assertRaises(m.Failure): m.cleanup([first, second], streams)
        self.assertEqual(stop.call_args_list, [mock.call(second), mock.call(first)])
        self.assertTrue(all(stream.closed for stream in streams))

    def test_environment_secret_and_fault_settings_not_inherited(self):
        with mock.patch.dict(os.environ, {'PGPASSWORD':'secret','DATABASE_URL':'secret','TEST_OTHER':'x','TURN_REGISTRY_FILE':'secret','RUST_LOG':'trace'}):
            env = m.clean_env()
        self.assertTrue(all(name not in env for name in ('PGPASSWORD','DATABASE_URL','TEST_OTHER','TURN_REGISTRY_FILE','RUST_LOG')))

    def test_progress_whitelist_does_not_copy_panic_or_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'sdk.log'
            path.write_text('capacity phase=hold\nsecret=private\ncapacity ready_pairs=500\nthread x panicked at secretfile\nprivate-value\nthread y panicked at /private/test/sdk_scale.rs:567:9:\n')
            rows = m.safe_progress(path)
            self.assertEqual(rows[:2], ['capacity phase=hold','capacity ready_pairs=500'])
            self.assertEqual(rows[-1], 'Rust assertion failed at sdk_scale.rs:567:9')
            self.assertNotIn('private', '\n'.join(rows).replace('private panic details withheld',''))

    def test_debug_mode_rejects_five_hundred_before_starting_services(self):
        argv = ['test-capacity.py', '--pg-bin', '/missing', '--redis-bin', '/missing',
                '--server-bin', '/missing', '--sdk-test', '/missing', '--output', '/missing',
                '--peers', '500', '--debug-close-only']
        with mock.patch.object(sys, 'argv', argv):
            with self.assertRaisesRegex(m.Failure, 'debug-only mode cannot be a 500 acceptance'):
                m.main()

    def test_event_diagnostics_accept_only_hashed_session_reference(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sdk.log'
            path.write_text('capacity event=closed endpoint=1 reason=rejected session_tag=0123456789abcdef\n'
                            'capacity event=closed endpoint=1 reason=rejected session=private-identity\n')
            rows = m.safe_progress(path)
            self.assertEqual(len(rows), 1)
            self.assertIn('session_tag=', rows[0])
            self.assertNotIn('private-identity', rows[0])

    def test_timing_and_baseline_only_fixed_numeric_fields(self):
        good = [
            'capacity phase=baseline elapsed_ms=42001',
            'capacity baseline_complete elapsed_ms=42041 snapshot_elapsed_ms=40 sessions=500',
            'capacity event=closed endpoint=251 reason=authorization_expired session_tag=0123456789abcdef elapsed_ms=49993',
            'capacity lease_baseline endpoint=251 session_tag=0123456789abcdef lease_generation=6 baseline_elapsed_ms=42041 event_elapsed_ms=49993 snapshot_elapsed_ms=40 source_baseline_remaining_ms=53000 target_baseline_remaining_ms=45000 source_event_remaining_ms=45048 target_event_remaining_ms=37048',
        ]
        bad = [good[0] + ' secret=synthetic', good[1].replace('40 sessions', 'secret sessions'),
               good[2].replace('0123456789abcdef', 'private-device-uuid'),
               good[3].replace('source_event_remaining_ms=45048', 'source_event_remaining_ms=1.5'),
               good[3].replace('lease_generation=6', 'lease_generation=' + '1' * 17),
               good[0].replace('baseline', 'private-token')]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sdk.log'; path.write_text('\n'.join(good + bad))
            self.assertEqual(m.safe_progress(path), good)

    def test_core_lease_diagnostics_enums_and_integer_bounds(self):
        stages = ('stale-generation', 'expired-before-update', 'expiry-conversion', 'maintenance-deadline', 'renewal-registration')
        good = [f'PeerloomTestDiag lease stage={stage} current=9 incoming=8 own_ack=true pending=false remaining_ms=51000' for stage in stages]
        bad = [good[0] + ' session=private', good[0].replace('stale-generation', 'unknown'),
               good[0].replace('own_ack=true', 'own_ack=secret'),
               good[0].replace('remaining_ms=51000', 'remaining_ms=' + '1' * 40),
               good[0].replace('current=9', 'current=-1')]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sdk.log'; path.write_text('\n'.join(good + bad))
            self.assertEqual(m.safe_progress(path), good)

    def test_shutdown_flood_cannot_evict_first_failure_or_phase(self):
        close = 'capacity event=closed endpoint=1 reason=closed session_tag=0123456789abcdef elapsed_ms=60000'
        early = ['capacity phase=hold elapsed_ms=40000'] + [close] * 300
        failure = ['PeerloomTestDiag lease stage=stale-generation current=9 incoming=8 own_ack=true pending=true remaining_ms=51000',
                   'thread test panicked at /private/sdk_scale.rs:540:13:']
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sdk.log'; path.write_text('\n'.join(early + [failure[0]] * 100 + failure + [close] * 5000 + ['capacity phase=shutdown elapsed_ms=61000']))
            rows = m.safe_progress(path)
        self.assertLessEqual(len(rows), 256)
        self.assertIn(early[0], rows)
        self.assertIn(failure[0], rows)
        self.assertIn('Rust assertion failed at sdk_scale.rs:540:13', rows)
        self.assertEqual(rows[-1], 'capacity phase=shutdown elapsed_ms=61000')

    def test_lease_diagnostics_only_explicit_test_child_not_inherited(self):
        with mock.patch.dict(os.environ, {'PEERLOOM_TEST_LEASE_DIAGNOSTICS': 'untrusted', 'TEST_CAPACITY_FIXTURE': 'secret'}, clear=True):
            self.assertNotIn('PEERLOOM_TEST_LEASE_DIAGNOSTICS', m.clean_env())
            env = m.sdk_environment(Path('/private/owned/fixture.json'))
        self.assertEqual(env['PEERLOOM_TEST_LEASE_DIAGNOSTICS'], '1')
        self.assertEqual(env['TEST_CAPACITY_FIXTURE'], '/private/owned/fixture.json')
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(m.sdk_environment(Path('/owned/fixture'))['PEERLOOM_TEST_LEASE_DIAGNOSTICS'], '1')

    def test_cpu_reused_pid_is_not_counted(self):
        previous={'1':{'birth':1,'ticks':10},'2':{'birth':2,'ticks':20}}
        current={'1':{'birth':9,'ticks':999999},'2':{'birth':2,'ticks':120}}
        self.assertEqual(m.cpu_delta(previous,current),100/os.sysconf('SC_CLK_TCK'))

    def test_proc_stat_comm_and_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'stat'
            fields=['S','2']+['0']*22
            fields[11]='10';fields[12]='20';fields[17]='8';fields[19]='123';fields[21]='100'
            path.write_text('42 (process name ) extra) '+' '.join(fields))
            result=m.proc_stat(path)
        self.assertEqual(result,{'ppid':2,'ticks':30,'threads':8,'birth':123,'rss':100*os.sysconf('SC_PAGE_SIZE')})


if __name__ == '__main__': unittest.main()
