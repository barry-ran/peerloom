#!/usr/bin/env python3
"""Host-only negative tests; no Windows features, WSL, processes or services are changed."""
import hashlib
import gzip
import tarfile
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
    def test_owned_import_has_explicit_null_stdin_and_captured_outputs(self):
        args = ['wsl.exe', '--import', 'PeerloomCI-' + 'a'*32,
                r'C:\owned\wsl', r'C:\owned\archive', '--version', '1']
        child = Mock(returncode=0)
        child.communicate.return_value = (b'completed', b'')
        with patch.object(service.subprocess, 'Popen', return_value=child) as spawn:
            self.assertEqual(service.run(args, import_diagnostic=True), b'completed')
            self.assertEqual(spawn.call_args.kwargs['stdin'], service.subprocess.DEVNULL)
            self.assertEqual(spawn.call_args.kwargs['stdout'], service.subprocess.PIPE)
            self.assertEqual(spawn.call_args.kwargs['stderr'], service.subprocess.PIPE)
            child.communicate.assert_called_once_with(timeout=180)
            spawn.assert_called_once()
        for argv, diagnostic in ((['postgres', '--version'], True), (args, False)):
            with patch.object(service.subprocess, 'Popen', return_value=child) as spawn:
                service.run(argv, import_diagnostic=diagnostic)
                self.assertIsNone(spawn.call_args.kwargs['stdin'])

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

    def test_owned_wsl_import_only_reports_codes_in_utf8_and_utf16(self):
        for encoding in ('utf-8', 'utf-16-le'):
            child = Mock(returncode=1)
            child.communicate.return_value = (('C:\\runner-private\\owned WSL_E_WSL1_NOT_SUPPORTED 0x8007019e').encode(encoding), b'')
            args = ['wsl.exe', '--import', 'PeerloomCI-' + 'a'*32, r'C:\runner-private\owned\wsl', r'C:\runner-private\owned\archive', '--version', '1']
            with patch.object(service.subprocess, 'Popen', return_value=child), patch('sys.stderr', new_callable=io.StringIO) as output:
                with self.assertRaisesRegex(RuntimeError, 'child command failed'):
                    service.run(args, import_diagnostic=True)
                text = output.getvalue()
            self.assertIn('WSL_E_WSL1_NOT_SUPPORTED', text)
            self.assertIn('0x8007019e', text)
            self.assertNotIn('private', text)
            self.assertLessEqual(len(text.encode('utf-8')), 1024)

    def test_import_redacts_owned_paths_home_ansi_and_bounds_utf8(self):
        root = r'C:\Users\private-user\runner\PeerloomCI-' + 'a'*32
        for encoding in ('utf-8', 'utf-16-le'):
            data = ('\x1b[31mImport failed at ' + root + '/archive\x00\n' + '错误' * 700).encode(encoding)
            text = service.wsl_import_diagnostic(-1, data, b'', [root, r'C:\Users\private-user'])
            self.assertNotIn('private-user', text)
            self.assertNotIn('PeerloomCI-', text)
            self.assertNotIn('\x1b', text)
            self.assertNotIn('\x00', text)
            self.assertLessEqual(len(text.encode('utf-8')), 1024)

    def test_oversize_diagnostic_never_exposes_partial_redaction(self):
        text = service.bounded_wsl_text(b'x'*8190 + b'private-home', ['private-home'])
        self.assertEqual(text, '[WSL diagnostic output exceeded safe input bound]')

    def test_readonly_status_diagnostic_no_mutation_or_secret_paths(self):
        result = service.subprocess.CompletedProcess(['wsl.exe', '--status'], 1, b'error at private-home', b'failure')
        with patch.object(service.subprocess, 'run', return_value=result) as probe, patch('sys.stderr', new_callable=io.StringIO) as output:
            service.wsl_status_diagnostic(['private-home'])
            self.assertNotIn('private-home', output.getvalue())
            self.assertIn('Read-only WSL status diagnostic:', output.getvalue())
            probe.assert_called_once_with(['wsl.exe', '--status'], stdin=service.subprocess.DEVNULL, stdout=service.subprocess.PIPE,
                                          stderr=service.subprocess.PIPE, timeout=20, check=False)

    def test_both_owned_diagnostic_stderr_paths_survive_actual_cp1252(self):
        argv = ['wsl.exe', '--import', 'PeerloomCI-' + 'a'*32,
                r'C:\private\owned\wsl', r'C:\private\owned\archive', '--version', '1']
        for status_only in (False, True):
            with self.subTest(status_only=status_only):
                sink = io.BytesIO()
                stderr = io.TextIOWrapper(sink, encoding='cp1252', errors='strict')
                raw = ('错误：句柄无效 ' + argv[3]).encode('utf-8')
                child = Mock(returncode=1)
                child.communicate.return_value = (raw, b'')
                result = service.subprocess.CompletedProcess(['wsl.exe'], 1, raw, b'')
                try:
                    with patch.object(service.sys, 'stderr', stderr), \
                         patch.object(service.subprocess, 'Popen', return_value=child), \
                         patch.object(service.subprocess, 'run', return_value=result):
                        if status_only:
                            service.wsl_status_diagnostic([argv[3]])
                        else:
                            with self.assertRaisesRegex(RuntimeError, 'child command failed'):
                                service.run(argv, import_diagnostic=True)
                    stderr.flush()
                    text = sink.getvalue().decode('utf-8')
                    self.assertIn('错误：句柄无效', text)
                    self.assertNotIn('private', text)
                    self.assertLessEqual(len(sink.getvalue()), 1024)
                    self.assertEqual(stderr.errors, 'strict')
                finally:
                    stderr.detach()

    def test_other_process_stderr_stays_private(self):
        child = Mock(returncode=1)
        child.communicate.return_value = (b'private stdout', b'private stderr')
        with patch.object(service.subprocess, 'Popen', return_value=child), patch('sys.stderr', new_callable=io.StringIO) as output:
            with self.assertRaises(RuntimeError):
                service.run(['postgres', 'private'], import_diagnostic=True)
            self.assertEqual(output.getvalue(), '')

    def test_unconfirmed_tree_cleanup_is_not_success(self):
        child = Mock(pid=12345)
        child.communicate.side_effect = service.subprocess.TimeoutExpired('cargo', 1)
        child.poll.return_value = None
        with patch.object(service.subprocess, 'Popen', return_value=child), patch.object(service.subprocess, 'run', return_value=service.subprocess.CompletedProcess([], 1)), patch.object(service.sys, 'platform', 'win32'):
            with self.assertRaisesRegex(RuntimeError, 'cleanup unconfirmed'):
                service.run(['cargo', 'test'], timeout=1)


class ImportProbeTest(unittest.TestCase):
    def test_preparation_only_never_imports_or_builds_services(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            args = ['windows-service.py', '--directory', temp, '--distro', 'PeerloomCI-'+'a'*32, '--prepare-import-only']
            with patch.object(service.sys, 'argv', args), patch.object(service, 'validate_scope', return_value=directory), patch.object(service, 'download') as download, patch.object(service, 'prepare_wsl_tar') as prepare, patch.object(service, 'run') as run:
                service.main()
                download.assert_called_once()
                self.assertEqual(download.call_args.args[0]['version'], '24.04.3')
                prepare.assert_called_once()
                run.assert_not_called()

    def test_diagnostic_only_is_bounded_redacted_and_does_not_execute(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            name = 'PeerloomCI-'+'a'*32
            (directory/'import-output.txt').write_text('The handle is invalid at '+temp+' '+name)
            args = ['windows-service.py', '--directory', temp, '--distro', name, '--diagnose-import-only', '--import-exit-code', '-1']
            with patch.object(service.sys, 'argv', args), patch.object(service, 'validate_scope', return_value=directory), patch.object(service, 'run') as run, patch('sys.stdout', new_callable=io.StringIO) as output:
                service.main()
                run.assert_not_called()
                self.assertIn('The handle is invalid', output.getvalue())
                self.assertNotIn(temp, output.getvalue())
                self.assertNotIn(name, output.getvalue())
                self.assertLessEqual(len(output.getvalue().encode()), 1024)

    def test_diagnostic_utf8_survives_actual_cp1252_stdout(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory/'import-output.txt').write_bytes(('错误：句柄无效 '+temp).encode('utf-8'))
            args = ['windows-service.py', '--directory', temp, '--distro', 'PeerloomCI-'+'a'*32,
                    '--diagnose-import-only', '--import-exit-code', '-1']
            sink = io.BytesIO()
            stdout = io.TextIOWrapper(sink, encoding='cp1252', errors='strict')
            try:
                with patch.object(service.sys, 'argv', args), patch.object(service, 'validate_scope', return_value=directory), patch.object(service.sys, 'stdout', stdout):
                    service.main()
                    stdout.flush()
                result = sink.getvalue().decode('utf-8', errors='strict')
                self.assertIn('错误：句柄无效', result)
                self.assertNotIn(temp, result)
                self.assertLessEqual(len(sink.getvalue()), 1024)
            finally:
                stdout.detach()

    def test_public_probe_keeps_secret_fixture_acl_and_never_recurses_rootfs(self):
        script = (ROOT/'test-windows-service.ps1').read_text(encoding='utf-8')
        acl_start = script.index('if (-not $ImportProbeOnly) {')
        acl_end = script.index('} else {', acl_start)
        private_acl = script[acl_start:acl_end]
        self.assertIn('$acl.SetAccessRuleProtection($true, $false)', private_acl)
        self.assertIn('Set-Acl -LiteralPath $directory -AclObject $acl', private_acl)
        self.assertEqual(script.count('Set-Acl -LiteralPath'), 1)
        self.assertIn('New-Item -ItemType Directory $directory -ErrorAction Stop', script)
        self.assertIn('PUBLIC_PROBE_REPARSE_ANCESTOR_FORBIDDEN', script)
        cleanup_start = script.index('# WSL unregister owns rootfs removal.')
        cleanup_end = script.index('    } else {', cleanup_start)
        public_cleanup = script[cleanup_start:cleanup_end]
        self.assertNotIn('-Recurse', public_cleanup)
        self.assertLess(public_cleanup.index('PUBLIC_PROBE_REPARSE_CLEANUP_ROOT_RETAINED'), public_cleanup.index('Get-ChildItem'))
        self.assertIn('PUBLIC_PROBE_NONEMPTY_REMAINDER_RETAINED', public_cleanup)
        self.assertIn('PUBLIC_PROBE_UNKNOWN_REMAINDER_RETAINED', public_cleanup)
        self.assertIn('PUBLIC_PROBE_REPARSE_REMAINDER_RETAINED', public_cleanup)
        self.assertIn('Public probe UUID absent and owned staging cleanup: PASS', public_cleanup)
        self.assertLess(script.index('OWNED_DISTRO_CLEANUP_INCOMPLETE_PRIVATE_DIRECTORY_RETAINED'), cleanup_start)

    def test_workflow_source_uses_utf8_under_windows_legacy_locale(self):
        original = Path.read_text
        def windows_default(path, encoding=None, errors=None):
            return original(path, encoding=encoding or 'cp1252', errors=errors)
        with patch.object(Path, 'read_text', windows_default):
            self.test_probe_is_early_single_direct_import_with_owned_cleanup()

    def test_probe_is_early_single_direct_import_with_owned_cleanup(self):
        script = (ROOT/'test-windows-service.ps1').read_text(encoding='utf-8')
        workflow = (ROOT.parent/'.github/workflows/native.yml').read_text(encoding='utf-8')
        self.assertEqual(script.count('& wsl.exe --import '), 1)
        self.assertLess(script.index('Owned direct import raw exit='), script.index('--diagnose-import-only'))
        self.assertIn("$drive.DriveFormat -ne 'NTFS'", script)
        self.assertIn("$drive.DriveType -ne 'Fixed'", script)
        self.assertIn('[System.IO.File]::OpenRead($tar)', script)
        self.assertIn('& wsl.exe --unregister $name', script)
        self.assertNotIn("throw 'OWNED_PROBE_UNREGISTER_FAILED'", script)
        self.assertIn("throw 'OWNED_DISTRO_CLEANUP_INCOMPLETE_PRIVATE_DIRECTORY_RETAINED'", script)
        self.assertIn("-contains $name", script)
        self.assertIn('& wsl.exe --distribution $name --exec /bin/true', script)
        self.assertIn('timeout-minutes: 8', workflow)
        self.assertLess(workflow.index('-ImportProbeOnly'), workflow.index('固定 Windows Rust 工具链'))
        self.assertIn('./scripts/test-windows.ps1\n          ./scripts/test-windows-service.ps1', workflow)


class PlainTarTest(unittest.TestCase):
    def fixture(self, directory):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w') as tar:
            item = tarfile.TarInfo('../not-extracted')
            item.size = 4
            tar.addfile(item, io.BytesIO(b'data'))
        plain = data.getvalue()
        compressed = gzip.compress(plain)
        archive = directory / 'ubuntu_base.archive'
        archive.write_bytes(compressed)
        return archive, plain, {'sha256': hashlib.sha256(compressed).hexdigest(),
                                'tar_size': len(plain), 'tar_sha256': hashlib.sha256(plain).hexdigest()}

    def test_pinned_gzip_becomes_exact_plain_tar_without_member_extraction(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            archive, plain, spec = self.fixture(directory)
            output = directory / 'ubuntu_base.tar'
            service.prepare_wsl_tar(archive, output, spec)
            self.assertEqual(output.read_bytes(), plain)
            self.assertEqual(sorted(p.name for p in directory.iterdir()), ['ubuntu_base.archive', 'ubuntu_base.tar'])
            self.assertFalse((directory.parent / 'not-extracted').exists())
            with self.assertRaises(FileExistsError):
                service.prepare_wsl_tar(archive, output, spec)
            self.assertEqual(output.read_bytes(), plain)

    def test_hash_size_and_corrupt_gzip_fail_without_partial_output(self):
        for mutation in ('source_hash', 'tar_hash', 'too_small', 'too_large', 'corrupt', 'bad_bound'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp:
                directory = Path(temp)
                archive, plain, spec = self.fixture(directory)
                output = directory / 'ubuntu_base.tar'
                if mutation == 'source_hash': spec['sha256'] = '0'*64
                if mutation == 'tar_hash': spec['tar_sha256'] = '0'*64
                if mutation == 'too_small': spec['tar_size'] -= 1
                if mutation == 'too_large': spec['tar_size'] += 1
                if mutation == 'bad_bound': spec['tar_size'] = 513*1024*1024
                if mutation == 'corrupt':
                    archive.write_bytes(archive.read_bytes()[:-5])
                    spec['sha256'] = hashlib.sha256(archive.read_bytes()).hexdigest()
                with self.assertRaises((ValueError, EOFError, OSError)):
                    service.prepare_wsl_tar(archive, output, spec)
                self.assertFalse(output.exists())

    def test_source_symlink_and_existing_output_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            archive, plain, spec = self.fixture(directory)
            output = directory / 'ubuntu_base.tar'
            # Mock the filesystem type check; Windows does not require symlink privileges.
            with patch.object(Path, 'is_symlink', return_value=True), self.assertRaises(ValueError):
                service.prepare_wsl_tar(archive, output, spec)
            output.write_bytes(b'preserved')
            with self.assertRaises(FileExistsError): service.prepare_wsl_tar(archive, output, spec)
            self.assertEqual(output.read_bytes(), b'preserved')

    def test_single_import_keeps_version_and_io_with_plain_tar_argument(self):
        source = (ROOT / 'windows-service.py').read_text(encoding='utf-8')
        self.assertIn("str(public / 'ubuntu_base.tar'), '--version', '1']", source)
        self.assertNotIn("str(directory / 'ubuntu_base.archive'), '--version', '1']", source)
        self.assertIn('stdin=subprocess.DEVNULL if owned_import else None', source)
        pins = json.loads((ROOT / 'windows-service-dependencies.json').read_text(encoding='utf-8'))['ubuntu_base']
        self.assertEqual(pins['tar_size'], 84101120)
        self.assertEqual(pins['tar_sha256'], 'c0bb584a1fe79db423329609b8c8280ca755e99fdee6be4555420061bdd08cde')


class PostgreSQLDiagnosticTest(unittest.TestCase):
    def test_exact_owned_startup_failure_redacts_generated_secrets_and_paths(self):
        directory=Path('/owned-private');secret='generated-password-'+'a'*32
        for stage,binary,tail in (('initdb','initdb.exe',[]),('start','pg_ctl.exe',['start'])):
            child=Mock(returncode=7)
            child.communicate.return_value=(b'', ('could not start at '+str(directory)+' secret='+secret).encode())
            argv=[str(directory/'postgresql/pgsql/bin'/binary),'-D',str(directory/'data'),*tail]
            with patch.object(service.subprocess,'Popen',return_value=child),patch('sys.stderr',new_callable=io.StringIO) as output,self.assertRaises(RuntimeError):
                service.run(argv,postgres_diagnostic=(stage,directory,[secret]))
            text=output.getvalue()
            self.assertIn('stage='+stage+' exit=7',text)
            self.assertIn('could not start',text)
            self.assertNotIn(secret,text);self.assertNotIn(str(directory),text)
            self.assertLessEqual(len(text.encode()),2048)

    def test_arbitrary_command_or_other_data_path_never_prints_capture(self):
        directory=Path('/owned-private');child=Mock(returncode=1);child.communicate.return_value=(b'private-output',b'private-error')
        for argv in (['psql','-D',str(directory/'data')],
                     [str(directory/'postgresql/pgsql/bin/pg_ctl.exe'),'-D','/other','start'],
                     [str(directory/'postgresql/pgsql/bin/pg_ctl.exe'),'-D',str(directory/'data'),'stop']):
            with patch.object(service.subprocess,'Popen',return_value=child),patch('sys.stderr',new_callable=io.StringIO) as output,self.assertRaises(RuntimeError):
                service.run(argv,postgres_diagnostic=('start',directory,[]))
            self.assertEqual(output.getvalue(),'')

    def test_pg_init_failure_precedes_and_prevents_wsl_import_or_build(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp);name='PeerloomCI-'+'a'*32;private=base/name;private.mkdir();public=base/(name+'-public');public.mkdir()
            args=['windows-service.py','--directory',str(private),'--distro',name,'--public-directory',str(public)]
            calls=[]
            def fail_init(argv,**kwargs):
                calls.append(argv)
                if Path(argv[0]).name=='postgres.exe':return b'postgres (PostgreSQL) 18.6'
                raise RuntimeError('synthetic init failure')
            with patch.object(service.sys,'argv',args),patch.object(service,'validate_scope',return_value=private),patch.object(service,'download'),patch.object(service,'extract_postgres'),patch.object(service,'free_port',return_value=16379),patch.object(service,'run',side_effect=fail_init),patch.object(service,'prepare_wsl_tar') as prepare,self.assertRaisesRegex(RuntimeError,'init failure'):
                service.main()
            self.assertEqual([Path(x[0]).name for x in calls],['postgres.exe','initdb.exe'])
            prepare.assert_not_called()
            source=(ROOT/'windows-service.py').read_text(encoding='utf-8')
            self.assertLess(source.index("STAGE = 'initialize-private-native-postgresql'"),source.index("STAGE = 'import-owned-wsl1'"))
            self.assertLess(source.index("STAGE = 'start-private-native-postgresql'"),source.index("STAGE = 'build-real-redis-in-owned-wsl1'"))

    def test_multibyte_control_secret_and_oversize_output_safe(self):
        secret='a'*43
        for data in (('错误 '+secret+' \x1b[31mprivatepath').encode('utf-8'),
                     ('错误 '+secret+' privatepath').encode('utf-16-le'), b'x'*9000+secret.encode()):
            text=service.postgres_startup_diagnostic('initdb',1,data,b'',Path('privatepath'),[secret])
            self.assertNotIn(secret,text);self.assertNotIn('privatepath',text);self.assertNotIn('\x1b',text)
            self.assertLessEqual(len(text.encode('utf-8')),2048)


class PrivateRedisTest(unittest.TestCase):
    def test_stdin_handle_closed_and_child_owned_before_return_no_secret_args_env(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp); config = directory/'redis.conf'; secret = 'a'*43
            config.write_bytes(service.redis_config(16379, secret))
            children, handles = [], []
            child = Mock()
            captured = {}
            def spawn(argv, **kwargs):
                captured.update(argv=argv, env=kwargs['env'], source=kwargs['stdin'], data=kwargs['stdin'].read())
                self.assertFalse(kwargs['stdin'].closed)
                return child
            with patch.object(service.subprocess, 'Popen', side_effect=spawn):
                service.launch_private_redis('PeerloomCI-'+'b'*32, config, directory/'redis.log', children, handles,
                    {'PATH':'safe', 'SYSTEMROOT':'system', 'PGPASSWORD':secret, 'GITHUB_TOKEN':secret, 'WSLENV':'PGPASSWORD', 'DATABASE_URL':secret})
            self.assertEqual(children, [child])
            self.assertTrue(captured['source'].closed)
            self.assertIn(secret.encode(), captured['data'])
            self.assertNotIn(secret, repr(captured['argv'])+repr(captured['env']))
            self.assertEqual(captured['env'], {'PATH':'safe', 'SYSTEMROOT':'system', 'WSLENV':''})
            self.assertIn('ulimit -c 0 && exec', captured['argv'][-1])
            for handle in handles: handle.close()

    def test_spawn_or_config_read_failure_closes_source_and_leaves_owned_logs(self):
        with tempfile.TemporaryDirectory() as temp:
            directory=Path(temp);config=directory/'redis.conf';config.write_bytes(service.redis_config(16379,'a'*43))
            children,handles=[],[];seen=[]
            def fail(*args, **kwargs):
                seen.append(kwargs['stdin']); raise OSError('synthetic start failure')
            with patch.object(service.subprocess,'Popen',side_effect=fail), self.assertRaises(OSError):
                service.launch_private_redis('owned',config,directory/'redis.log',children,handles,{})
            self.assertTrue(seen[0].closed);self.assertEqual(children,[])
            for handle in handles:handle.close()
            config.write_bytes(b'x'*1025)
            with patch.object(service.subprocess,'Popen') as spawn,self.assertRaises(ValueError):
                service.launch_private_redis('owned',config,directory/'second.log',[],[],{})
            spawn.assert_not_called()
            config.unlink()
            with self.assertRaises(ValueError):service.launch_private_redis('owned',config,directory/'missing.log',[],[],{})

    def test_config_inputs_and_effective_persistence_fail_closed(self):
        for port,password in ((0,'a'*43),(65536,'a'*43),(True,'a'*43),(16379,'bad\nconfig')):
            with self.assertRaises(ValueError):service.redis_config(port,password)
        data=service.redis_config(16379,'a'*43)
        self.assertLessEqual(len(data),1024)
        for setting in (b'save ""',b'appendonly no',b'daemonize no',b'syslog-enabled no',b'logfile ""'):
            self.assertIn(setting,data)
        for reply in (b'*17\r\n',b'$1025\r\n',b'*1\r\n*0\r\n',b'$3\r\nab'):
            with self.assertRaises(RuntimeError):service.redis_response(io.BytesIO(reply))

    def test_effective_config_mismatch_is_not_readiness_success(self):
        def bulk(data): return b'$'+str(len(data)).encode()+b'\r\n'+data+b'\r\n'
        fields=[b'save',b'',b'appendonly',b'no',b'daemonize',b'no',b'logfile',b'',b'syslog-enabled',b'no']
        for index in (1,3,5,7,9):
            altered=list(fields);altered[index]=b'unsafe'
            reply=b'+OK\r\n+PONG\r\n'+bulk(b'peerloom-ci')+b'*10\r\n'+b''.join(bulk(x) for x in altered)
            sock=Mock();sock.makefile.return_value=io.BytesIO(reply)
            context=Mock();context.__enter__=Mock(return_value=sock);context.__exit__=Mock(return_value=False)
            with patch.object(service.socket,'create_connection',return_value=context),self.assertRaisesRegex(RuntimeError,'configuration unsafe'):
                service.redis_ready(16379,'a'*43)

    def test_child_is_registered_even_if_parent_stdin_close_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            directory=Path(temp);config=directory/'redis.conf';config.write_bytes(service.redis_config(16379,'a'*43))
            original=Path.open;children=[];handles=[];child=Mock()
            class ClosingFailure:
                def __init__(self, file): self.file=file
                def __enter__(self): return self.file
                def __exit__(self,*args): self.file.close();raise OSError('synthetic close failure')
            def opened(path,*args,**kwargs):
                file=original(path,*args,**kwargs)
                return ClosingFailure(file) if path==config and args==('rb',) else file
            with patch.object(Path,'open',opened),patch.object(service.subprocess,'Popen',return_value=child),self.assertRaises(OSError):
                service.launch_private_redis('owned',config,directory/'redis.log',children,handles,{})
            self.assertEqual(children,[child])
            for handle in handles:handle.close()

    def test_public_rootfs_never_receives_secret_config_and_cleanup_retains_failure(self):
        source=(ROOT/'windows-service.py').read_text(encoding='utf-8')
        script=(ROOT/'test-windows-service.ps1').read_text(encoding='utf-8')
        self.assertNotIn("'/root/peerloom-ci/redis.conf'",source)
        self.assertNotIn("wsl('/bin/cp', config",source)
        self.assertIn("launch_private_redis(args.distro, config, directory / 'redis.log'",source)
        self.assertIn('if ($publicCreated -and',script)
        self.assertLess(script.index('New-Item -ItemType Directory $publicDirectory'),script.index('$publicCreated = $true'))
        self.assertIn('if ($fullSucceeded)',script)
        self.assertIn('protected task logs retained',script)
        self.assertIn('$acl.SetAccessRuleProtection($true, $false)',script)


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
            with patch.object(service.urllib.request, 'urlopen', return_value=Response(data)) as fetch:
                service.download(good, destination)
                request = fetch.call_args.args[0]
                self.assertEqual(request.full_url, good['url'])
                self.assertEqual(request.get_header('User-agent'), 'Peerloom-CI/0.1 (+https://github.com/barry-ran/peerloom)')
                self.assertEqual(fetch.call_args.kwargs['timeout'], 60)
            self.assertEqual(destination.read_bytes(), data)
            with self.assertRaises(ValueError):
                service.download({**good, 'url': 'https://other.example/archive'}, destination)
            with patch.object(service.urllib.request, 'urlopen', return_value=Response(data)), self.assertRaises(ValueError):
                service.download({**good, 'sha256': '0' * 64}, Path(temp) / 'tampered')
            redirected = Response(data)
            redirected.url = 'https://other.example/archive'
            with patch.object(service.urllib.request, 'urlopen', return_value=redirected), self.assertRaises(ValueError):
                service.download(good, Path(temp) / 'redirect')

    def test_http_status_diagnostic_has_no_url_body_or_headers(self):
        error = service.urllib.error.HTTPError('https://example.invalid/?secret=hidden', 403,
                                               'private body', {'Authorization': 'secret'}, io.BytesIO(b'private'))
        message = service.failure_summary('download-redis', error)
        self.assertEqual(message, 'Windows service acceptance failed: stage=download-redis category=HTTPError http_status=403')
        self.assertNotIn('hidden', message)
        self.assertNotIn('private', message)
        self.assertNotIn('Authorization', message)
        self.assertNotIn('http_status', service.failure_summary('download-redis', ValueError('secret')))

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
        dependencies = json.loads((ROOT / 'windows-service-dependencies.json').read_text(encoding='utf-8'))
        self.assertEqual(dependencies['postgresql']['version'], '18.6')
        self.assertEqual(dependencies['redis']['version'], '8.10.3')
        for spec in dependencies.values():
            self.assertRegex(spec['sha256'], r'^[a-f0-9]{64}$')
            self.assertEqual(service.urllib.parse.urlparse(spec['url']).scheme, 'https')
            self.assertIn(service.urllib.parse.urlparse(spec['url']).hostname, service.HOSTS)

    def test_no_privileged_or_global_mutation_fallback(self):
        source = (ROOT / 'windows-service.py').read_text(encoding='utf-8') + (ROOT / 'test-windows-service.ps1').read_text(encoding='utf-8')
        for forbidden in ('--set-default', '--shutdown', '--install', 'Enable-WindowsOptionalFeature', 'Start-Service', '-Verb RunAs', 'netsh', 'Set-NetFirewall'):
            self.assertNotIn(forbidden, source)
        self.assertIn("'--version', '1'", source)
        self.assertIn("'--unregister', args.distro", source)


if __name__ == '__main__':
    unittest.main()
