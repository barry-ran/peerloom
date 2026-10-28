#!/usr/bin/env python3
"""Controller ownership/cleanup tests only; not actual Docker/Rust evidence."""
import importlib.util
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import time
import signal
import unittest
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location('control', Path(__file__).with_name('test-control-recovery.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Tests(unittest.TestCase):
    def test_only_disposable_projects_and_services(self):
        for name in ('production', 'peerloom-test-x-y', 'peerloom-test-1-2;bad', ''):
            with self.assertRaises(ValueError):
                m.compose(name)
        with self.assertRaises(ValueError):
            m.verify_owner([], 'peerloom-test-1-2', 'postgres')

    def test_exact_project_and_service_labels(self):
        for project, service in [('other', 'redis'), ('peerloom-test-1-2', 'postgres')]:
            replies = [MagicMock(stdout=b'a'*64), MagicMock(stdout=json.dumps([
                {'Config': {'Labels': {'com.docker.compose.project': project,
                                      'com.docker.compose.service': service}}}]).encode())]
            with patch.object(m, 'run', side_effect=replies), self.assertRaises(ValueError):
                m.verify_owner([], 'peerloom-test-1-2', 'redis')

    def exercise(self, failure=None, cleanup_failure=False):
        calls = []
        def run(args, **kw):
            calls.append(args)
            if failure == 'stop' and 'stop' in args:
                raise TimeoutError('uncertain stop')
            return MagicMock(stdout=b'')
        process = MagicMock()
        process.wait.return_value = 7 if failure == 'test' else 0
        process.poll.return_value = 0
        with tempfile.TemporaryDirectory() as tmp, patch.object(m, 'run', side_effect=run), \
                patch.object(m, 'verify_owner', return_value='a'*64), \
                patch.object(m, 'wait_marker'), patch.object(m.time, 'sleep'), \
                patch.object(m.subprocess, 'Popen', return_value=process), \
                patch.object(m, 'reap', side_effect=RuntimeError('cleanup') if cleanup_failure else None):
            if failure or cleanup_failure:
                with self.assertRaises((RuntimeError, TimeoutError)):
                    m.scenario(['docker', 'compose'], 'peerloom-test-1-2', 'redis',
                               'http://127.0.0.1:18080', '/private/admin', Path(tmp))
            else:
                m.scenario(['docker', 'compose'], 'peerloom-test-1-2', 'redis',
                           'http://127.0.0.1:18080', '/private/admin', Path(tmp))
        self.assertIn('up', calls[-1])
        self.assertIn('--no-deps', calls[-1])
        self.assertEqual(calls[-1][-1], 'redis')
        self.assertTrue(all('down' not in call and '--volumes' not in call for call in calls))

    def test_success_restores(self): self.exercise()
    def test_failed_sdk_restores(self): self.exercise('test')
    def test_uncertain_stop_restores(self): self.exercise('stop')
    def test_failed_child_cleanup_still_restores(self): self.exercise(cleanup_failure=True)


    def test_real_sigterm_restores_owned_service(self):
        harness = r"""
import importlib.util, sys, time
from pathlib import Path
from unittest.mock import MagicMock
spec = importlib.util.spec_from_file_location('control', sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
root = Path(sys.argv[2])
def run(args, **kw):
    if 'up' in args: (root / 'restored').write_text('restored')
    return MagicMock(stdout=b'')
m.run = run
m.verify_owner = lambda *args: 'a'*64
m.wait_marker = lambda *args: None
m.reap = lambda process: (root / 'reaped').write_text('reaped')
m.subprocess.Popen = lambda *args, **kw: MagicMock()
m.install_interrupt_handlers()
try:
    m.scenario(['docker', 'compose'], 'peerloom-test-1-2', 'redis',
               'http://127.0.0.1:18080', '/private/admin', root)
except InterruptedError:
    sys.exit(23)
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            process = subprocess.Popen([sys.executable, '-c', harness, str(Path(m.__file__)), tmp])
            try:
                deadline = time.monotonic() + 5
                while not (root / 'down').exists():
                    self.assertIsNone(process.poll())
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
                process.send_signal(signal.SIGTERM)
                self.assertEqual(process.wait(timeout=5), 23)
                self.assertTrue((root / 'restored').exists())
                self.assertTrue((root / 'reaped').exists())
            finally:
                if process.poll() is None:
                    process.kill(); process.wait(timeout=5)

    def test_missing_marker_does_not_loop_after_sdk_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            process = MagicMock()
            process.poll.return_value = 1
            with self.assertRaises(RuntimeError):
                m.wait_marker(Path(tmp), 'ready', process, 3)


if __name__ == '__main__':
    unittest.main()
