#!/usr/bin/env python3
"""托管 ICE helper 的输入边界与拥有子进程清理回归。"""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

SPEC = importlib.util.spec_from_file_location('managed_relay', Path(__file__).with_name('test-managed-relay.py'))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class HelperTests(unittest.TestCase):
    def test_origin_is_numeric_loopback_without_credentials(self):
        for value in ('http://127.0.0.1:18080', 'https://[::1]:443/'):
            MODULE.validate_origin(value)
        for value in ('http://localhost:18080', 'http://192.0.2.1',
                      'http://user@127.0.0.1', 'http://127.0.0.1/a',
                      'http://127.0.0.1?secret=x', 'http://127.0.0.1:0'):
            with self.subTest(value=value), self.assertRaises(MODULE.Failure):
                MODULE.validate_origin(value)

    def test_fixture_mode_symlink_and_size(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture'
            path.write_bytes(b'abc')
            path.chmod(0o600)
            self.assertEqual(MODULE.private_bytes(path, 3), b'abc')
            with self.assertRaises(MODULE.Failure):
                MODULE.private_bytes(path, 2)
            path.chmod(0o644)
            with self.assertRaises(MODULE.Failure):
                MODULE.private_bytes(path, 3)
            path.chmod(0o600)
            alias = Path(directory) / 'alias'
            alias.symlink_to(path)
            with self.assertRaises(OSError):
                MODULE.private_bytes(alias, 3)

    def test_pair_requires_device_audience(self):
        device = {'application_id': '11111111-1111-4111-8111-111111111111',
                  'device_id': '22222222-2222-4222-8222-222222222222',
                  'device_credential': 'dev_' + 'a' * 43,
                  'expires_at': '2099-01-01T00:00:00Z'}
        pair = {'source': dict(device), 'target': dict(device)}
        MODULE.validate_pair(json.dumps(pair).encode())
        pair['source']['device_credential'] = 'svc_' + 'a' * 43
        with self.assertRaises(MODULE.Failure):
            MODULE.validate_pair(json.dumps(pair).encode())

    def test_lease_probe_has_separate_service_audience(self):
        MODULE.validate_lease_probe(json.dumps({'service_credential': 'svc_' + 'a' * 43}).encode())
        for value in ({}, {'service_credential': 'dev_' + 'a' * 43}):
            with self.assertRaises(MODULE.Failure):
                MODULE.validate_lease_probe(json.dumps(value).encode())

    @patch.object(MODULE.subprocess, 'Popen')
    def test_sdk_has_owned_process_group_and_scoped_environment(self, popen):
        process = popen.return_value
        process.wait.return_value = 0
        process.poll.return_value = 0
        MODULE.run_sdk(Path('/private/pair.json'), 'http://127.0.0.1:18080', Path('/private/admin.json'))
        args, kwargs = popen.call_args
        self.assertTrue(kwargs['start_new_session'])
        self.assertEqual(kwargs['env']['TEST_MANAGED_RELAY'], '1')
        self.assertEqual(kwargs['env']['TEST_SIGNAL_FIXTURE_FILE'], '/private/pair.json')
        self.assertNotIn('/private/pair.json', args[0])
        self.assertEqual(kwargs['env']['TEST_LEASE_ADMIN_FIXTURE'], '/private/admin.json')
        process.wait.assert_called_once_with(timeout=180)

    @patch.object(MODULE.os, 'killpg')
    @patch.object(MODULE.subprocess, 'Popen')
    def test_timeout_terminates_owned_group(self, popen, killpg):
        process = popen.return_value
        process.pid = 12345
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired('cargo', 180), 0]
        with self.assertRaises(subprocess.TimeoutExpired):
            MODULE.run_sdk(Path('/private/pair.json'), 'http://127.0.0.1:18080', Path('/private/admin.json'))
        killpg.assert_called_once_with(12345, signal.SIGTERM)


if __name__ == '__main__':
    unittest.main()
