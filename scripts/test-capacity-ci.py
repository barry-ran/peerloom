#!/usr/bin/env python3
# MIT — Copyright (c) 2026 Peerloom contributors.
import importlib.util
import json
from pathlib import Path
import subprocess
import signal
import time
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('capacity_ci', HERE / 'run-capacity-ci.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class CapacityCI(unittest.TestCase):
    def test_exact_test_artifact_selection(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary)/'sdk_scale'; binary.write_bytes(b'binary')
            item = {'reason':'compiler-artifact','target':{'name':'sdk_scale','kind':['test']},'executable':str(binary)}
            self.assertEqual(m.select_executable(json.dumps(item).encode()), binary)
            for data in (b'', (json.dumps(item)+'\n'+json.dumps(item)).encode(), json.dumps(dict(item,target={'name':'other','kind':['test']})).encode()):
                with self.assertRaises(ValueError): m.select_executable(data)

    def test_only_public_fixed_results_exported(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); runtime=root/'runtime'; runtime.mkdir(); output=root/'output'; output.mkdir()
            (runtime/'capacity-result.json').write_text('{"status":"failed"}')
            (runtime/'private').mkdir(); (runtime/'private'/'secret.log').write_text('DO-NOT-UPLOAD')
            (runtime/'unknown.json').write_text('{}')
            m.export_results(runtime,output)
            self.assertEqual([p.name for p in output.iterdir()], ['capacity-result.json'])

    def test_symlink_evidence_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); out=root/'out'; out.mkdir(); secret=root/'secret'; secret.write_text('{}')
            (root/'capacity-result.json').symlink_to(secret)
            with self.assertRaises(ValueError): m.export_results(root,out)

    def test_clean_exact_source_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); (root/'file').write_bytes(b'original\r\n')
            with mock.patch.object(m,'command',side_effect=[b'a'*40+b'\n',b'',b'file\0']):
                result=m.source_manifest(root,'a'*40)
                self.assertEqual(result['working_tree_sha256']['file'],m.hashlib.sha256(b'original\r\n').hexdigest())
            with mock.patch.object(m,'command',return_value=b'b'*40):
                with self.assertRaises(ValueError): m.source_manifest(root,'a'*40)
            with mock.patch.object(m,'command',side_effect=[b'a'*40,b' M file']):
                with self.assertRaises(ValueError): m.source_manifest(root,'a'*40)

    def test_controller_nonzero_never_soft_passes(self):
        process=mock.Mock(); process.poll.return_value=1; process.wait.return_value=1
        with mock.patch.object(m.subprocess,'Popen',return_value=process):
            with self.assertRaises(RuntimeError): m.run_controller(['fixture'])
        process.wait.assert_called_once_with(timeout=1260)

    def test_timeout_signals_controller_for_owned_cleanup(self):
        process=mock.Mock(); process.poll.return_value=None; process.wait.side_effect=[subprocess.TimeoutExpired('fixture',1260),0]
        with mock.patch.object(m.subprocess,'Popen',return_value=process):
            with self.assertRaisesRegex(RuntimeError,'deadline'): m.run_controller(['fixture'])
        process.terminate.assert_called_once(); process.kill.assert_not_called()

    def test_cleanup_timeout_fails_unconfirmed(self):
        process=mock.Mock(); process.poll.return_value=None; process.wait.side_effect=[subprocess.TimeoutExpired('fixture',1260),subprocess.TimeoutExpired('fixture',60),-9]
        with mock.patch.object(m.subprocess,'Popen',return_value=process):
            with self.assertRaisesRegex(RuntimeError,'unconfirmed'): m.run_controller(['fixture'])
        process.kill.assert_called_once()

    def test_real_wrapper_repeated_termination_reaps_controller(self):
        for interrupt in (signal.SIGTERM, signal.SIGINT):
            with tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary); ready=root/'ready'; reaped=root/'reaped'
                child=root/'child.py'
                child.write_text("import signal,time,pathlib\ndef stop(*args):\n time.sleep(.25)\n pathlib.Path("+repr(str(reaped))+").write_text('reaped')\n raise SystemExit(0)\nsignal.signal(signal.SIGTERM,stop)\npathlib.Path("+repr(str(ready))+").write_text('ready')\ntime.sleep(10)\n")
                wrapper=root/'wrapper.py'
                wrapper.write_text("import importlib.util\ns=importlib.util.spec_from_file_location('runner',"+repr(str(HERE/'run-capacity-ci.py'))+")\nm=importlib.util.module_from_spec(s);s.loader.exec_module(m)\nm.install_interrupt_handlers()\nm.run_controller(["+repr(sys.executable)+","+repr(str(child))+"])\n")
                process=subprocess.Popen([sys.executable,str(wrapper)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                try:
                    deadline=time.monotonic()+5
                    while not ready.exists():
                        self.assertLess(time.monotonic(),deadline); time.sleep(.01)
                    process.send_signal(interrupt); time.sleep(.05)
                    process.send_signal(interrupt)
                    self.assertNotEqual(process.wait(timeout=5),0)
                    self.assertEqual(reaped.read_text(),'reaped')
                finally:
                    if process.poll() is None: process.kill(); process.wait(timeout=5)


    def test_workflow_keeps_mandatory_500_and_no_private_upload(self):
        workflow=(HERE.parent/'.github/workflows/ci.yml').read_text(encoding='utf-8').split('\n  capacity-500:',1)[1]
        self.assertIn('runs-on: ubuntu-24.04',workflow)
        self.assertIn('timeout-minutes: 60',workflow)
        for name in ('CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG', 'CARGO_INCREMENTAL'):
            self.assertIn(name + ": '0'", workflow)
        self.assertNotIn('continue-on-error',workflow)
        self.assertNotIn('sudo ',workflow)
        self.assertNotIn('ulimit ',workflow)
        upload=workflow.split('path: |',1)[1]
        self.assertNotIn('*',upload)
        self.assertEqual(len([x for x in upload.splitlines() if x.strip()]),4)
        source=(HERE/'run-capacity-ci.py').read_text(encoding='utf-8')
        self.assertIn("'--peers', '500'",source)
        self.assertNotIn('setrlimit',source)


if __name__ == '__main__': unittest.main()
