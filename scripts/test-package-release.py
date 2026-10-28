#!/usr/bin/env python3
import importlib.util
import json
import os
from contextlib import nullcontext
from pathlib import Path
import tempfile
import tarfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('package', Path(__file__).with_name('package-release.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

producer_spec = importlib.util.spec_from_file_location('producer', Path(__file__).with_name('package-third-party.py'))
producer = importlib.util.module_from_spec(producer_spec)
producer_spec.loader.exec_module(producer)

class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'src/device-sdk').mkdir(parents=True)
        (self.root / 'src/device-sdk/Cargo.toml').write_text('[workspace.package]\nversion="0.1.0"\n', encoding='utf-8')
        (self.root / 'src/device-sdk/Cargo.lock').write_text('lock', encoding='utf-8')
        (self.root / 'LICENSE').write_text('project license', encoding='utf-8')
        (self.root / 'third_party/rust').mkdir(parents=True)
        self.proof = self.root / 'dist/third-party'; self.proof.mkdir(parents=True)
        self.evidence('collected-not-legally-reviewed')
        self.library = self.root / 'release.so'; self.library.write_bytes(b'real-test-fixture-not-binary')
        self.output = self.root / 'package'

    def evidence(self, status):
        record = {'ecosystem': 'cargo', 'name': 'fixture', 'version': '1.0.0', 'archive_sha256': 'a'*64, 'purl': 'pkg:cargo/fixture@1.0.0', 'issues': [] if status == 'collected-not-legally-reviewed' else ['LICENSE_TEXT_MISSING'], 'files': [{'file':'第三方告知.md','source_path':'LICENSE','sha256': m.hashlib.sha256(b'original evidence').hexdigest()}]}
        (self.proof / 'report.json').write_text(json.dumps({'format_version':1, 'issues':[], 'packages':[record], 'evidence_status':status}), encoding='utf-8')
        (self.proof / 'sbom.cdx.json').write_text('{}', encoding='utf-8')
        (self.proof / '第三方告知.md').write_text('original evidence', encoding='utf-8')
        (self.proof / 'SHA256SUMS').write_text(''.join(f'{m.digest(p)}  {p.name}\n' for p in sorted(self.proof.iterdir()) if p.name != 'SHA256SUMS'), encoding='utf-8')

    def finish(self):
        with patch.dict(m.os.environ, {}, clear=True):
            m.finish(self.root, self.output, 'linux-x86_64', 'a'*40, [(self.library, 'sdk/lib/library.so')])

    def test_metadata_and_all_file_checksums(self):
        self.finish()
        metadata = json.loads((self.output / 'release-metadata.json').read_text(encoding='utf-8'))
        self.assertEqual(metadata['version'], '0.1.0')
        self.assertEqual(metadata['commit'], 'a'*40)
        self.assertEqual(metadata['build_profile'], 'release')
        self.assertTrue(metadata['release_evidence_complete'])
        entries = (self.output / 'SHA256SUMS').read_text(encoding='utf-8').splitlines()
        names = set()
        for line in entries:
            expected, name = line.split('  ', 1); names.add(name)
            self.assertEqual(m.digest(self.output/name), expected)
        self.assertEqual(names, {p.relative_to(self.output).as_posix() for p in self.output.rglob('*') if p.is_file()}-{'SHA256SUMS'})

    def test_linux_tar_preserves_executable_and_internal_checksums(self):
        self.library.chmod(0o755)
        native_stat = Path.stat
        def fixture_posix_stat(path, *args, **kwargs):
            result = native_stat(path, *args, **kwargs)
            if path in (self.library, self.output/'sdk/lib/library.so'):
                fields = list(result)
                fields[0] = (fields[0] & ~0o777) | 0o755
                return os.stat_result(fields)
            return result
        # NTFS chmod does not model POSIX executable bits. Only these fixture
        # files get POSIX stat metadata; real copy/tar/checksum logic still runs.
        # POSIX runners continue to exercise real on-disk executable bits.
        context = patch.object(Path, 'stat', fixture_posix_stat) if os.name == 'nt' else nullcontext()
        with context:
            self.finish()
        self.assertFalse((self.output/'sdk').exists())
        with tarfile.open(self.output/'peerloom-linux-x86_64.tar.gz', 'r:gz') as archive:
            members = archive.getmembers()
            self.assertTrue(all(m.isfile() and not m.issym() and not m.islnk() for m in members))
            self.assertEqual(archive.getmember('sdk/lib/library.so').mode, 0o755)
            self.assertEqual(archive.getmember('LICENSE').mode, 0o644)
            sums = archive.extractfile('SHA256SUMS').read().decode().splitlines()
            names = set()
            for line in sums:
                expected, name = line.split('  ', 1); names.add(name)
                self.assertEqual(m.hashlib.sha256(archive.extractfile(name).read()).hexdigest(), expected)
            self.assertEqual(names, {member.name for member in members} - {'SHA256SUMS'})

    def test_incomplete_is_not_release_eligible(self):
        self.evidence('incomplete'); self.finish()
        self.assertFalse(json.loads((self.output/'release-metadata.json').read_text(encoding='utf-8'))['release_evidence_complete'])

    def test_tampered_report_rejected(self):
        (self.proof/'report.json').write_text('{}', encoding='utf-8')
        with self.assertRaisesRegex(m.PackageError, 'CHECKSUM'): self.finish()

    def test_exact_documented_gap_keeps_original_report_and_incomplete_flag(self):
        (name, version), (checksum, provenance) = next(iter(m.GAPS.KNOWN.items()))
        record = {'ecosystem':'cargo','name':name,'version':version,'purl':f'pkg:cargo/{name}@{version}',
                  'archive_sha256':checksum,'provenance':provenance,'declared_license':'Apache-2.0/MIT',
                  'issues':['LICENSE_TEXT_MISSING'],'files':[]}
        report = {'format_version':1,'evidence_status':'incomplete','issues':[],'packages':[record]}
        raw = json.dumps(report).encode()
        (self.proof/'report.json').write_bytes(raw)
        (self.proof/'SHA256SUMS').write_text(''.join(f'{m.digest(p)}  {p.name}\n' for p in sorted(self.proof.iterdir()) if p.name != 'SHA256SUMS'), encoding='utf-8')
        self.finish()
        meta = json.loads((self.output/'release-metadata.json').read_text(encoding='utf-8'))
        self.assertFalse(meta['release_evidence_complete'])
        self.assertTrue(meta['release_delivery_eligible'])
        self.assertEqual(meta['evidence']['cargo_go'], m.GAPS.DOCUMENTED)
        self.assertEqual(meta['documented_gaps'][0]['archive_sha256'], checksum)
        self.assertEqual((self.output/'third-party/cargo-go-all-lock-candidates/report.json').read_bytes(), raw)
        self.assertEqual(meta['legal_review'], 'not-performed')

    def maven_proof(self):
        import shutil
        destination=self.root/'maven-proof'
        shutil.copytree(Path(__file__).with_name('testdata')/'maven-gap-proof',destination)
        (destination/'report.json').write_text(json.dumps(m.MAVEN.PINS['expected_report']),encoding='utf-8')
        (destination/'sbom.cdx.json').write_text('{}',encoding='utf-8')
        self.seal_maven(destination)
        return destination

    def seal_maven(self,directory):
        (directory/'SHA256SUMS').write_text(''.join(f'{m.digest(p)}  {p.relative_to(directory).as_posix()}\n' for p in sorted(directory.rglob('*')) if p.is_file() and p.name!='SHA256SUMS'),encoding='utf-8')

    def test_android_exact_documented_gaps_preserve_raw_incomplete_report(self):
        proof=self.maven_proof();raw=(proof/'report.json').read_bytes()
        with patch.dict(m.os.environ,{},clear=True):
            m.finish(self.root,self.output,'android','a'*40,[(self.library,'library-release.aar'),(self.root/'LICENSE','include/device_sdk.h')],proof)
        meta=json.loads((self.output/'release-metadata.json').read_text(encoding='utf-8'))
        self.assertFalse(meta['release_evidence_complete']);self.assertTrue(meta['release_delivery_eligible'])
        self.assertEqual(meta['evidence']['maven'],m.MAVEN.DOCUMENTED)
        self.assertEqual(len(meta['maven_documented_gaps']),19)
        self.assertEqual((self.output/'third-party/maven-configurations/report.json').read_bytes(),raw)

    def test_android_missing_bound_pom_is_rejected_even_after_reseal(self):
        proof=self.maven_proof();next((proof/'poms').glob('*.xml')).unlink();self.seal_maven(proof)
        with patch.dict(m.os.environ,{},clear=True),self.assertRaises(m.PackageError):
            m.finish(self.root,self.output,'android','a'*40,[(self.library,'library-release.aar')],proof)

    def test_symlink_input_rejected(self):
        self.library.unlink(); self.library.symlink_to(self.root/'LICENSE')
        with self.assertRaisesRegex(m.PackageError, 'SYMLINK'): self.finish()

    def test_existing_output_rejected(self):
        self.output.mkdir()
        with self.assertRaisesRegex(m.PackageError, 'OUTPUT'): self.finish()

    def test_unlisted_extra_rejected(self):
        (self.proof/'unreviewed.txt').write_text('not in verified manifest', encoding='utf-8')
        with self.assertRaisesRegex(m.PackageError, 'UNLISTED'): self.finish()

    def test_casefold_duplicate_rejected(self):
        (self.proof/'LICENSE').write_text('first', encoding='utf-8')
        (self.proof/'license').write_text('second', encoding='utf-8')
        self.evidence('collected-not-legally-reviewed')
        observed = {path.name for path in self.proof.iterdir()}
        if {'LICENSE', 'license'} <= observed:
            # Keep the real directory regression on case-sensitive filesystems.
            with self.assertRaisesRegex(m.PackageError, 'CASEFOLD'):
                self.finish()
            (self.proof/'license').unlink()
            self.evidence('collected-not-legally-reviewed')
        # A case-insensitive macOS volume cannot physically retain both entries.
        # Always supply a hostile enumeration too: real checksum reads and the
        # production collision guard are used, with no platform test skip.
        entries = list(self.proof.rglob('*'))
        existing = next(path for path in entries if path.name.casefold() == 'license')
        alias = 'license' if existing.name == 'LICENSE' else 'LICENSE'
        entries.append(self.proof/alias)
        with patch.object(Path, 'rglob', return_value=iter(entries)):
            with self.assertRaisesRegex(m.PackageError, 'CASEFOLD'):
                self.finish()

    def test_reserved_windows_name_rejected(self):
        if os.name != 'nt':
            (self.proof/'CON.txt').write_text('ambiguous', encoding='utf-8')
            self.evidence('collected-not-legally-reviewed')
            with self.assertRaisesRegex(m.PackageError, 'AMBIGUOUS'): self.finish()
            (self.proof/'CON.txt').unlink()
            self.evidence('collected-not-legally-reviewed')
        # Windows routes this spelling to a device, not an ordinary file.
        # A hostile listing tests the same production name guard on every OS.
        entries = [*self.proof.rglob('*'), self.proof/'CON.txt']
        with patch.object(Path, 'rglob', return_value=iter(entries)):
            with self.assertRaisesRegex(m.PackageError, 'AMBIGUOUS'): self.finish()

    def test_owned_status_is_incrementally_checksummed(self):
        producer.write_status(self.proof, 0)
        producer.append_owned_manifest(self.proof, {'发布审查状态.txt': producer.sha_file(self.proof/'发布审查状态.txt')})
        m.check_evidence(self.proof)

    def test_unknown_extra_cannot_be_sealed_by_producer(self):
        (self.proof/'unknown.txt').write_text('not owned', encoding='utf-8')
        (self.proof/'发布审查状态.txt').write_text('owned', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'unlisted'):
            producer.append_owned_manifest(self.proof, {'发布审查状态.txt': producer.sha_file(self.proof/'发布审查状态.txt')})

    def test_producer_does_not_reseal_changed_existing_bytes(self):
        (self.proof/'report.json').write_text('changed', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'bytes changed'):
            producer.append_owned_manifest(self.proof, {})

    def test_producer_checks_expected_new_bytes(self):
        (self.proof/'new.txt').write_text('unexpected', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'bytes changed'):
            producer.append_owned_manifest(self.proof, {'new.txt': 'a'*64})

    def test_only_declared_build_sources_added(self):
        admin = self.root/'third_party/admin-web-build'; admin.mkdir()
        (admin/'inventory.json').write_text('original inventory', encoding='utf-8')
        (self.root/'src/admin-web').mkdir()
        (self.root/'src/admin-web/package-lock.json').write_text('original lock', encoding='utf-8')
        vendor = self.root/'third_party/rust/nix-0.31.3'; (vendor/'crate').mkdir(parents=True)
        for name in ('crate/LICENSE', '来源.json', '上游补丁.patch', '应用补丁.patch', '回移说明.md'):
            (vendor/name).write_text('original '+name, encoding='utf-8')
        producer.copy_build_notices(self.root, self.proof)
        m.check_evidence(self.proof)
        self.assertEqual((self.proof/'vendor/nix-0.31.3/LICENSE').read_text(encoding='utf-8'), 'original crate/LICENSE')
        with self.assertRaisesRegex(ValueError, 'existing'):
            producer.copy_build_notices(self.root, self.proof)

    def test_wrong_commit_rejected(self):
        with self.assertRaisesRegex(m.PackageError, 'COMMIT'):
            m.finish(self.root,self.output,'linux-x86_64','branch',[])

    def test_nondefault_features_rejected(self):
        with patch.dict(m.os.environ, {'PEERLOOM_CARGO_FEATURES':'diagnostics'}):
            with self.assertRaisesRegex(m.PackageError, 'NONDEFAULT'):
                m.finish(self.root,self.output,'linux-x86_64','a'*40,[])

class WindowsEncodingTests(unittest.TestCase):
    def test_all_reachable_fixture_suites_under_cp1252_defaults(self):
        # CPython on Windows can default text files to cp1252. Do not globally
        # force UTF-8: run the real fixture suites with that hostile default.
        import io
        original_open = io.open
        def windows_open(file, mode='r', buffering=-1, encoding=None, *args, **kwargs):
            if 'b' not in mode and encoding in (None, 'locale'):
                encoding = 'cp1252'
            return original_open(file, mode, buffering, encoding, *args, **kwargs)
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(PackageTests)
        for filename in ('test-maven-gap-policy.py', 'test-package-third-party.py', 'test-third-party.py',
                         'test-windows-service-script.py'):
            spec = importlib.util.spec_from_file_location('encoding_fixture_' + filename,
                                                        Path(__file__).with_name(filename))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(module))
        import sys
        output = io.StringIO()
        stdout = io.TextIOWrapper(io.BytesIO(), encoding='cp1252', errors='strict')
        stderr = io.TextIOWrapper(io.BytesIO(), encoding='cp1252', errors='strict')
        try:
            with patch.object(io, 'open', windows_open), patch.object(sys, 'stdout', stdout), patch.object(sys, 'stderr', stderr):
                result = unittest.TextTestRunner(stream=output).run(suite)
        finally:
            stdout.close(); stderr.close()
        self.assertTrue(result.wasSuccessful(), output.getvalue())
        self.assertGreaterEqual(result.testsRun, 50)
        print(f"Windows cp1252 fixture suites: {result.testsRun} run, {len(result.skipped)} declared skips, no failures")

    def test_collector_reads_unicode_toml_under_cp1252(self):
        spec = importlib.util.spec_from_file_location('encoding_collector',
            Path(__file__).with_name('generate-third-party.py'))
        collector = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(collector)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sdk = root / 'src/device-sdk'
            (sdk / 'member').mkdir(parents=True)
            go = root / 'src/device-server'
            go.mkdir()
            comment = '# 中文 “原文”\n'
            (sdk / 'Cargo.toml').write_text(comment + '[workspace]\nmembers=["member"]\n[workspace.package]\nversion="0.1.0"\n', encoding='utf-8')
            (sdk / 'Cargo.lock').write_text(comment + '[[package]]\nname="fixture"\nversion="0.1.0"\n', encoding='utf-8')
            (sdk / 'member/Cargo.toml').write_text(comment + '[package]\nname="fixture"\nversion={workspace=true}\n', encoding='utf-8')
            (go / 'go.sum').write_text('', encoding='utf-8')
            original = Path.read_text
            def windows_read(path, encoding=None, **kwargs):
                return original(path, encoding=encoding or 'cp1252', **kwargs)
            with patch.object(Path, 'read_text', windows_read), patch.object(collector, 'run',
                    side_effect=['{"Main":true}', str(root / 'unused-cache')]):
                self.assertEqual(collector.collect(root), ([], {}, []))

    def test_tool_json_stdout_uses_utf8_without_locale_text_mode(self):
        import subprocess
        spec = importlib.util.spec_from_file_location('encoding_tool_collector',
            Path(__file__).with_name('generate-third-party.py'))
        collector = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(collector)
        payload = json.dumps({'Path': 'example.test/module', 'description': '中文 “原文”',
                              'authors': ['作者']}, ensure_ascii=False)
        reply = subprocess.CompletedProcess(['go'], 0, payload.encode('utf-8'), b'')
        with patch.object(collector.subprocess, 'run', return_value=reply) as run:
            self.assertEqual(collector.run(['go', 'list', '-m', '-json'], Path('.')), payload)
        self.assertNotIn('text', run.call_args.kwargs)
        self.assertNotIn('universal_newlines', run.call_args.kwargs)

    def test_reachable_repository_text_reads_and_writes_declare_utf8(self):
        import ast
        # Explicit Windows workflow call graph, including imported/subprocess
        # helpers. Binary evidence copies intentionally retain original bytes.
        files = ('windows-service.py', 'test-windows-service-script.py',
                 'test-management.py', 'test-package-release.py',
                 'package-release.py', 'package-third-party.py',
                 'generate-third-party.py', 'license-gap-policy.py')
        omissions = []
        for filename in files:
            source = Path(__file__).with_name(filename).read_text(encoding='utf-8')
            for node in ast.walk(ast.parse(source)):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr in ('read_text', 'write_text')):
                    encodings = [keyword.value for keyword in node.keywords if keyword.arg == 'encoding']
                    # ASCII-only synthetic import-output fixture is not repository
                    # source/config/report text; its writer remains owner-scoped.
                    if filename == 'test-windows-service-script.py' and node.func.attr == 'write_text':
                        continue
                    if not encodings or not isinstance(encodings[0], ast.Constant) or encodings[0].value != 'utf-8':
                        omissions.append(f'{filename}:{node.lineno}:{node.func.attr}')
        self.assertEqual(omissions, [])


if __name__ == '__main__': unittest.main()
