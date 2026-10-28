#!/usr/bin/env python3
"""无 AVD/Docker/管理员变更的边界回归；真实验收由两个 emulator job 执行。"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import signal
import sys
import time
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('control', ROOT / 'service-control.py')
control = importlib.util.module_from_spec(spec)
spec.loader.exec_module(control)
A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
G = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'
S = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd'


class Client:
    def __init__(self):
        self.calls = []
        self.grants = [dict(id=G, source_device_id=A, target_device_id=B, revoked_at=None)]
        self.sessions = [dict(id=S, source_device_id=A, target_device_id=B, grant_id=G, state='connected')]
        self.revoked = False

    def request(self, method, path, expected, credential, **_kwargs):
        self.calls.append((method, path, expected))
        assert credential == 'host-only-secret'
        if path.endswith('?limit=100'):
            return {'items': self.grants if 'connection-grants' in path else self.sessions}
        if method == 'DELETE':
            self.revoked = True
            return {'revoked': True}
        if 'connection-grants' in path:
            return {**self.grants[0], 'revoked_at': 'now' if self.revoked else None}
        return {**self.sessions[0], 'state': 'closed' if self.revoked else 'connected',
                'close_reason': 'GRANT_REVOKED' if self.revoked else None}


class Runner:
    def __init__(self, markers=()):
        self.calls = []
        self.markers = iter(markers)
        self.avd = b'peerloom-ci-16384\nOK\n'
        self.fail_stop = False

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if args[-2:] == ['avd', 'name']:
            return SimpleNamespace(stdout=self.avd)
        if 'stop' in args and self.fail_stop:
            raise subprocess.TimeoutExpired(args, 20)
        if 'head -c 33' in args[-1]:
            return SimpleNamespace(stdout=next(self.markers).encode())
        return SimpleNamespace(stdout=b'')


class Tests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {'GITHUB_ACTIONS': 'true'})
        self.env.start()
        self.addCleanup(self.env.stop)

    def make(self, runner=None, client=None):
        return control.Controller(Path('/owned'), 'emulator-5554', 'peerloom-ci-16384',
                                  'peerloom-android-1-2', client or Client(), 'host-only-secret',
                                  (A, B), runner or Runner())

    def test_phase_order_and_duplicate_do_not_repeat_mutations(self):
        runner = Runner()
        value = self.make(runner)
        with patch.object(control.time, 'sleep'):
            for phase in control.PHASES:
                value.step(phase)
                value.step(phase)
        self.assertEqual(value.index, 3)
        compose = [args for args, _ in runner.calls if args[0] == 'docker']
        self.assertEqual(len(compose), 2)
        self.assertEqual(compose[0][-4:], ['stop', '-t', '1', 'gateway'])
        self.assertEqual(compose[1][-2:], ['start', 'gateway'])
        self.assertNotIn('host-only-secret', repr(runner.calls))

    def test_unknown_or_out_of_order_marker_never_executes(self):
        for phase in ('$(touch /tmp/x)', 'network_resume', 'revoke_grant', 'network_pause;whoami'):
            runner = Runner()
            with self.assertRaises(RuntimeError):
                self.make(runner).step(phase)
            self.assertFalse(runner.calls)

    def test_foreign_serial_avd_and_project_are_refused(self):
        runner = Runner()
        runner.avd = b'not-owned\n'
        with self.assertRaises(RuntimeError):
            self.make(runner).step('network_pause')
        self.assertFalse(any(args[0] == 'docker' for args, _ in runner.calls))
        for serial, project in (('USB-DEVICE', 'peerloom-android-1-2'), ('emulator-5554', 'existing-project')):
            with self.assertRaises(RuntimeError):
                control.Controller(Path('/owned'), serial, 'peerloom-ci-16384', project, Client(), 'secret', (A, B), runner)

    def test_revoke_requires_exact_one_active_pair_and_matching_session(self):
        for case in ('no-grant', 'duplicate', 'wrong-session'):
            client = Client()
            if case == 'no-grant': client.grants[0]['target_device_id'] = A
            if case == 'duplicate': client.grants.append(dict(client.grants[0]))
            if case == 'wrong-session': client.sessions[0]['grant_id'] = S
            with self.assertRaises(RuntimeError): self.make(client=client).revoke()
            self.assertFalse(any(method == 'DELETE' for method, _, _ in client.calls))

    def test_real_contract_shape_revoke_then_readback_closed(self):
        client = Client()
        self.make(client=client).revoke()
        self.assertEqual(sum(method == 'DELETE' for method, _, _ in client.calls), 1)
        self.assertEqual(client.calls[-1][1], '/v1/sessions/' + S)

    def test_unknown_after_pause_restores_only_own_gateway(self):
        runner = Runner(('network_pause', 'bad-marker'))
        with patch.object(control.time, 'sleep'), self.assertRaises(RuntimeError):
            self.make(runner).execute()
        compose = [args for args, _ in runner.calls if args[0] == 'docker']
        self.assertEqual(compose[-1][-2:], ['start', 'gateway'])
        self.assertTrue(all('peerloom-android-1-2' in args for args in compose))

    def test_stop_timeout_still_attempts_restoration_and_fails(self):
        runner = Runner(('network_pause',))
        runner.fail_stop = True
        with self.assertRaises(subprocess.TimeoutExpired): self.make(runner).execute()
        self.assertEqual([args for args, _ in runner.calls if args[0] == 'docker'][-1][-2:], ['start', 'gateway'])

    def test_bounded_deadline_and_no_ci_permission_fallback(self):
        with patch.object(control.time, 'monotonic', side_effect=[0, 151]), self.assertRaises(RuntimeError):
            self.make().execute()
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'false'}), self.assertRaises(RuntimeError):
            self.make()

    def test_private_pair_rejects_mode_and_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'pair'
            path.write_text(json.dumps({'source': {'device_id': A}, 'target': {'device_id': B}}))
            path.chmod(0o600)
            self.assertEqual(control.private_pair(path), (A, B))
            path.chmod(0o644)
            with self.assertRaises(RuntimeError): control.private_pair(path)
            link = Path(temporary) / 'link'
            link.symlink_to(path)
            with self.assertRaises(OSError): control.private_pair(link)

    @unittest.skipUnless(os.name == 'posix', 'POSIX CI signal cleanup')
    def test_real_sigterm_and_duplicate_do_not_interrupt_restoration(self):
        program = r"""
import importlib.util, os, sys, time
from pathlib import Path
spec=importlib.util.spec_from_file_location('c',sys.argv[1]); c=importlib.util.module_from_spec(spec); spec.loader.exec_module(c)
os.environ['GITHUB_ACTIONS']='true'
class Probe(c.Controller):
    def __init__(self):
        super().__init__(Path('/owned'),'emulator-5554','peerloom-ci-16384','peerloom-android-1-2',None,'host-only',('a','b'))
        self.paused=True
    def compose(self, args):
        assert args==['start','gateway']
        print('restoring',flush=True)
        time.sleep(.3)
        print('restored',flush=True)
    def adb(self, args, **kwargs):
        print('waiting',flush=True)
        time.sleep(5)
c.install_shutdown_handlers()
try: Probe().execute()
except RuntimeError: sys.exit(1)
"""
        process = subprocess.Popen([sys.executable, '-c', program, str(ROOT / 'service-control.py')], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(process.stdout.readline().strip(), 'waiting')
            process.send_signal(signal.SIGTERM)
            self.assertEqual(process.stdout.readline().strip(), 'restoring')
            process.send_signal(signal.SIGTERM)
            output, errors = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 1)
            self.assertEqual(output.strip(), 'restored')
            self.assertEqual(errors, '')
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)

    def test_instrumentation_keeps_admin_host_only_and_no_close_fake_revocation(self):
        script = (ROOT / 'run-instrumentation.sh').read_text()
        self.assertIn('for name in registration-fixture.json pair-fixture.json;', script)
        self.assertIn("trap 'exit 143' TERM", script)
        self.assertIn("trap 'exit 130' INT", script)
        self.assertEqual(script.count("trap '' TERM INT"), 2)
        self.assertNotIn('for name in admin.json', script)
        test = (ROOT.parent / 'library/src/androidTest/java/io/peerloom/sdk/ServiceTest.kt').read_text()
        self.assertIn('hostPhase("revoke_grant")', test)
        self.assertNotIn('await(ca.close())', test)
        self.assertIn('assertEquals(1, sourceClosed.get())', test)
        manifest = (ROOT.parent / 'library/src/androidTest/AndroidManifest.xml').read_text()
        self.assertIn('BackgroundProbeActivity" android:exported="false"', manifest)
        self.assertNotIn('BackgroundProbeActivity', (ROOT.parent / 'library/src/main/AndroidManifest.xml').read_text())


if __name__ == '__main__':
    unittest.main()
