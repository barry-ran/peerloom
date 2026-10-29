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
            m.export_results(runtime, results := {}, {}, 'core')
            self.assertEqual(results, {'core': {'status':'failed'}})
            self.assertEqual(list(output.iterdir()), [])

    def test_symlink_evidence_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); out=root/'out'; out.mkdir(); secret=root/'secret'; secret.write_text('{}')
            (root/'capacity-result.json').symlink_to(secret)
            with self.assertRaises(ValueError): m.export_results(root,{}, {}, 'core')

    def test_build_ffi_is_native_c_and_exact_target_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); workspace=root/'src/device-sdk'
            adapter=workspace/'device-ffi/tests/capacity_host.c'; adapter.parent.mkdir(parents=True); adapter.write_bytes(b'fixture source')
            header=workspace/'device-ffi/include/device_sdk.h'; header.parent.mkdir(); header.write_bytes(b'fixture header')
            binary=root/'ffi_scale'; binary.write_bytes(b'fixture executable')
            private=root/'private'; private.mkdir(); calls=[]
            def command(args, cwd, timeout=1200):
                calls.append(args)
                if args[0]=='gcc': Path(args[-1]).write_bytes(b'object')
                elif args[0]=='ar': Path(args[2]).write_bytes(b'archive')
                elif args[0]=='cargo':
                    return json.dumps({'reason':'compiler-artifact','target':{'name':'ffi_scale','kind':['test']},'executable':str(binary)}).encode()
                else: return (m.CASES['ffi'][2]+': test\n').encode()
                return b''
            with mock.patch.object(m,'command',side_effect=command):
                executable,binding=m.build_test(root,private,'ffi')
            self.assertEqual(executable,binary)
            self.assertEqual([c[0] for c in calls],['gcc','ar','cargo',str(binary)])
            self.assertIn('-Werror',calls[0]); self.assertIn('rustc',calls[2])
            self.assertIn('peerloom_capacity_c_host',calls[2]); self.assertNotIn('RUSTFLAGS',calls[2])
            self.assertEqual(binding['c_adapter_source_sha256'],m.digest(adapter))
            self.assertEqual(binding['c_header_sha256'],m.digest(header))
            self.assertEqual(binding['sdk_test_sha256'],m.digest(binary))

    def test_zero_or_wrong_named_test_never_counts_as_acceptance(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); binary=root/'sdk';binary.write_bytes(b'fixture')
            item={'reason':'compiler-artifact','target':{'name':'sdk_scale','kind':['test']},'executable':str(binary)}
            for listing in (b'',b'other: test\n', (m.CASES['core'][2]+': test\nother: test\n').encode()):
                with mock.patch.object(m,'command',side_effect=[json.dumps(item).encode(),listing]):
                    with self.assertRaisesRegex(ValueError,'expected real test'):m.build_test(root,root,'core')

    def test_two_cases_serial_separate_private_runtime_and_bound_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); output=root/'out';output.mkdir();manifest=root/'source.json';manifest.write_text('{}')
            built={case:(root/case,{'sdk_test_sha256':case,'c_adapter_source_sha256':'adapter'}) for case in m.CASES};order=[]
            def controller(args):
                case=args[args.index('--case')+1];order.append(case)
                runtime=Path(args[args.index('--output')+1]);runtime.mkdir()
                result={'case':case,'status':'passed','requested_peers':500,'owned_processes_reaped':True,
                        'sdk_test_sha256':case,'source_manifest_sha256':m.digest(manifest),'c_adapter_source_sha256':'adapter','samples':1}
                (runtime/'capacity-result.json').write_text(json.dumps(result));(runtime/'resource-samples.json').write_text(json.dumps([{'elapsed_seconds':1.0,'rss':1024,'fds':3,'threads':2,'cpu_seconds':0.5}]))
                (runtime/'private-secret.log').write_text('never upload')
            with mock.patch.object(m,'run_controller',side_effect=controller):
                m.run_cases(root,root,root,{'postgresql':root,'redis':root},built,manifest,output)
            self.assertEqual(order,['core','ffi'])
            result=json.loads((output/'capacity-result.json').read_text())
            self.assertEqual(result['status'],'passed');self.assertEqual(set(result['cases']),set(m.CASES))
            self.assertEqual(set(p.name for p in output.iterdir()),set(m.PUBLIC_RESULTS))
            self.assertTrue((root/'runtime-core').is_dir() and (root/'runtime-ffi').is_dir())

    def test_second_case_failure_retains_first_proof_but_never_overall_passes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);output=root/'out';output.mkdir();manifest=root/'source.json';manifest.write_text('{}')
            built={case:(root/case,{'sdk_test_sha256':case,'c_adapter_source_sha256':'adapter'}) for case in m.CASES}
            def controller(args):
                case=args[-1];runtime=Path(args[args.index('--output')+1]);runtime.mkdir()
                result={'case':case,'status':'passed' if case=='core' else 'failed','requested_peers':500,
                        'owned_processes_reaped':True,'sdk_test_sha256':case,'source_manifest_sha256':m.digest(manifest)}
                (runtime/'capacity-result.json').write_text(json.dumps(result));(runtime/'resource-samples.json').write_text(json.dumps([{'elapsed_seconds':1.0,'rss':1024,'fds':3,'threads':2,'cpu_seconds':0.5}]))
                if case=='ffi':raise RuntimeError('actual fixture failure')
            with mock.patch.object(m,'run_controller',side_effect=controller),self.assertRaises(RuntimeError):
                m.run_cases(root,root,root,{'postgresql':root,'redis':root},built,manifest,output)
            report=json.loads((output/'capacity-result.json').read_text())
            self.assertEqual(report['status'],'failed');self.assertEqual(report['cases']['core']['status'],'passed')
            self.assertEqual(report['cases']['ffi']['status'],'failed')

    def test_complete_requires_both_nonempty_numeric_resource_series(self):
        sample={'elapsed_seconds':1.0,'rss':1024,'fds':3,'threads':2,'cpu_seconds':0.5}
        results={case:{'status':'passed','owned_processes_reaped':True,'samples':1} for case in m.CASES}
        valid={case:[dict(sample)] for case in m.CASES}
        with tempfile.TemporaryDirectory() as temporary:
            output=Path(temporary)
            m.write_results(output,results,valid,complete=True)
            bads=[{'core':[sample]},dict(valid,ffi=[]),dict(valid,ffi='not-samples'),
                  dict(valid,ffi=[dict(sample,rss='1024')]),dict(valid,ffi=[dict(sample,fds=True)]),
                  dict(valid,ffi=[dict(sample,cpu_seconds=float('nan'))]),
                  dict(valid,ffi=[dict(sample,secret='not-public')]),
                  dict(valid,ffi=[sample,sample])]
            for rows in bads:
                with self.subTest(rows=rows),self.assertRaises(ValueError):m.write_results(output,results,rows,complete=True)
            # Partial failure evidence remains exportable, but never becomes a success.
            m.write_results(output,{'core':results['core']},{},complete=False)
            self.assertEqual(json.loads((output/'capacity-result.json').read_text())['status'],'failed')

    def test_missing_failed_wrong_case_binary_or_adapter_proof_rejected(self):
        binding={'sdk_test_sha256':'binary','c_adapter_source_sha256':'adapter'}
        valid={'case':'ffi','status':'passed','requested_peers':500,'owned_processes_reaped':True,
               'sdk_test_sha256':'binary','source_manifest_sha256':'source','c_adapter_source_sha256':'adapter'}
        m.validate_case_result(valid,'ffi',binding,'source')
        for key in valid:
            value=dict(valid);value.pop(key)
            with self.subTest(key=key),self.assertRaises(ValueError):m.validate_case_result(value,'ffi',binding,'source')
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):m.write_results(Path(temporary),{'core':valid},{},complete=True)
            with self.assertRaises(ValueError):m.write_results(Path(temporary),{'core':valid,'ffi':dict(valid,status='failed')},{},complete=True)

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
        self.assertIn("'--features', 'test-diagnostics'",source)
        self.assertNotIn('setrlimit',source)


if __name__ == '__main__': unittest.main()
