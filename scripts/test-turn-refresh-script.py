#!/usr/bin/env python3
"""Refresh脚本协议边界与容器清理单测；不冒充实际TURN网络验收。"""
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location('turn_refresh', Path(__file__).with_name('test-turn-refresh.py'))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RefreshScriptTests(unittest.TestCase):
    def test_standard_integrity_and_tamper_rejection(self):
        transaction = b't' * 12
        key = b'only-test-key'
        data = MODULE.packet(0x0104, transaction, [(0x000D, b'\0\0\0<')], key)
        kind, attrs = MODULE.parse(data, transaction)
        self.assertEqual(kind, 0x0104)
        MODULE.verify_integrity(data, attrs, key)
        with self.assertRaises(RuntimeError):
            MODULE.verify_integrity(data, attrs, b'wrong-test-key')
        with self.assertRaises(RuntimeError):
            MODULE.parse(data[:-1], transaction)
        with self.assertRaises(RuntimeError):
            MODULE.parse(data, b'x' * 12)

    def test_container_security_and_no_secret_arguments(self):
        with patch.object(MODULE.os, 'getuid', return_value=1000), patch.object(MODULE.os, 'getgid', return_value=1000):
            command = MODULE.container_command('peerloom-turn-test:local', 'owned-name', Path('/tmp/private'))
        self.assertIn('--read-only', command)
        self.assertEqual(command[command.index('--pull') + 1], 'never')
        self.assertEqual(command[command.index('--cap-drop') + 1], 'ALL')
        self.assertEqual(command[command.index('--user') + 1], '1000:1000')
        self.assertIn('no-new-privileges:true', command)
        self.assertIn('type=bind,src=/tmp/private/turn.conf,dst=/etc/coturn/turnserver.conf,readonly', command)
        self.assertNotIn('static-auth-secret', ' '.join(command))
        with patch.object(MODULE.os, 'getuid', return_value=0):
            with self.assertRaises(RuntimeError):
                MODULE.container_command('image', 'name', Path('/tmp/private'))

    def test_cleanup_removes_exact_container_and_waits(self):
        process = Mock()
        with patch.object(MODULE.subprocess, 'run', return_value=Mock(returncode=0)) as run:
            MODULE.stop_server(process, 'owned-name')
        self.assertEqual(run.call_args.args[0], ['docker', 'rm', '-f', '-v', 'owned-name'])
        process.terminate.assert_called_once()
        process.wait.assert_called_once_with(timeout=10)

    def test_cleanup_failure_is_not_silent_and_client_still_stops(self):
        process = Mock()
        with patch.object(MODULE.subprocess, 'run', side_effect=subprocess.TimeoutExpired('docker', 15)):
            with self.assertRaises(RuntimeError):
                MODULE.stop_server(process, 'owned-name')
        process.terminate.assert_called_once()
        process.wait.assert_called_once_with(timeout=10)


if __name__ == '__main__':
    unittest.main()
