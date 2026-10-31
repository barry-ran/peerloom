#!/usr/bin/env python3
"""发布管理器纯本地安全回归；所有 API/删除均为 mock。"""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location('admin', Path(__file__).with_name('release-admin.py'))
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)
P = A.P
SHA, MASTER, TREE = '1' * 40, '2' * 40, '3' * 40

def sums(files):
    return ''.join(hashlib.sha256(v).hexdigest() + '  ' + n + '\n' for n, v in sorted(files.items())).encode()

def package(platform='windows-x86_64'):
    meta = {'format_version': 1, 'platform': platform, 'product': 'server' if platform == 'server-linux-amd64' else 'sdk', 'commit': SHA, 'version': '0.1.0',
            'build_profile': 'release', 'cargo_features': 'not-applicable' if platform == 'server-linux-amd64' else 'default', 'release_evidence_complete': True,
            'evidence': {'cargo_go': 'collected-not-legally-reviewed'}}
    if platform == 'android':
        meta['evidence']['maven'] = 'collected-not-legally-reviewed'
    files = {'LICENSE': b'MIT', 'release-metadata.json': json.dumps(meta).encode()}
    scopes = ['cargo-go-all-lock-candidates'] + (['maven-configurations'] if platform == 'android' else [])
    for scope in scopes:
        prefix = 'third-party/' + scope + '/'
        record = {'ecosystem':'cargo', 'name':'fixture', 'version':'1', 'archive_sha256':'a'*64, 'issues':[], 'files':[{'file':'LICENSE','source_path':'LICENSE','sha256':hashlib.sha256(b'license fixture').hexdigest()}]}
        proof = {'report.json': json.dumps({'evidence_status':'collected-not-legally-reviewed', 'format_version':1, 'issues':[], 'packages':[record]}).encode(), 'sbom.cdx.json': b'{}', 'LICENSE': b'license fixture'}
        files.update({prefix + n: v for n, v in proof.items()})
        files[prefix + 'SHA256SUMS'] = sums(proof)
    if platform == 'android':
        files.update({'library-release.aar': b'AAR fixture', 'include/device_sdk.h': b'header'})
    if platform == 'windows-x86_64':
        files.update({'lib/device_ffi.dll': b'DLL fixture', 'lib/device_ffi.dll.lib': b'import fixture', 'lib/device_ffi.lib': b'static fixture', 'include/device_sdk.h': b'header'})
    return files, meta

def write_zip(path, files, checksum=True):
    with zipfile.ZipFile(path, 'w') as archive:
        for name, data in files.items():
            archive.writestr(name, data)
        if checksum:
            archive.writestr('SHA256SUMS', sums(files))

def installation_package(platform='server-linux-amd64', extra=None, omit=None, bad_mode=None, bad_binary=False):
    files, meta = package(platform)
    files['安装说明.txt'] = b'install the checked tar payload'
    required = (P.SERVER_BINARIES | P.SERVER_DEPLOY | P.SERVER_SQL | P.SERVER_DOCS
                if platform == 'server-linux-amd64' else P.LINUX_SDK_FILES)
    installed = {name: b'fixture deployment or binary' for name in required}
    installed.update(extra or {})
    if omit:
        installed.pop(omit, None)
    executable = P.SERVER_BINARIES | {'deploy/init-private.py'} if platform == 'server-linux-amd64' else set()
    meta['executable_files'] = sorted(executable)
    meta['installation_payload'] = P.INSTALL_PAYLOADS[platform]
    files['release-metadata.json'] = json.dumps(meta).encode()
    members = dict(files, **installed)
    members['SHA256SUMS'] = sums(members)
    if bad_binary:
        members['bin/device-server'] = b'tampered after checksum'
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:gz') as out:
        for name, data in members.items():
            item = tarfile.TarInfo(name)
            item.size = len(data)
            item.mode = 0o755 if name in executable else 0o644
            if name == bad_mode:
                item.mode = 0o644
            out.addfile(item, io.BytesIO(data))
    files[meta['installation_payload']] = stream.getvalue()
    return files, meta


class ServerSplitPolicyTests(unittest.TestCase):
    def verify(self, files, platform='server-linux-amd64'):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'package.zip'
            write_zip(path, files)
            return P.verify_zip(path, platform, SHA, '0.1.0')

    def test_server_and_sdk_are_independent_complete_packages(self):
        self.verify(installation_package()[0])
        self.verify(installation_package('linux-x86_64')[0], 'linux-x86_64')
        self.assertEqual(P.PLATFORMS['server-linux-amd64'], 'ci.yml')
        self.assertEqual(len(P.PLATFORMS), 5)

    def test_all_server_files_are_required(self):
        for name in P.SERVER_BINARIES | P.SERVER_DEPLOY | P.SERVER_SQL | P.SERVER_DOCS:
            with self.subTest(name=name), self.assertRaises(P.Rejected):
                self.verify(installation_package(omit=name)[0])

    def test_server_unknown_files_and_wrong_modes_rejected(self):
        for name in ('bin/unknown', 'deploy/secret.env', 'infra/migrations/tests/unsafe.sql', 'sdk/lib/libdevice_ffi.so'):
            with self.subTest(name=name), self.assertRaisesRegex(P.Rejected, 'UNEXPECTED_INSTALL'):
                self.verify(installation_package(extra={name: b'unknown'})[0])
        with self.assertRaisesRegex(P.Rejected, 'MODES'):
            self.verify(installation_package(bad_mode='bin/device-server')[0])

    def test_binary_tamper_and_outer_unknown_rejected(self):
        with self.assertRaisesRegex(P.Rejected, 'COVERAGE'):
            self.verify(installation_package(bad_binary=True)[0])
        files, _ = installation_package()
        files['undeclared-root.txt'] = b'even with a recomputed outer checksum'
        with self.assertRaises(P.Rejected):
            self.verify(files)

    def test_product_and_platform_are_not_interchangeable(self):
        for field, value in [('product', 'sdk'), ('platform', 'linux-x86_64'), ('cargo_features', 'default')]:
            files, meta = installation_package()
            meta[field] = value
            files['release-metadata.json'] = json.dumps(meta).encode()
            with self.subTest(field=field), self.assertRaisesRegex(P.Rejected, 'IDENTITY'):
                self.verify(files)
        for value in (None, 'server'):
            files, meta = package()
            meta['product'] = value
            files['release-metadata.json'] = json.dumps(meta).encode()
            with self.assertRaisesRegex(P.Rejected, 'IDENTITY'):
                self.verify(files, 'windows-x86_64')

    def test_public_names_explicitly_separate_server_and_sdk(self):
        self.assertEqual(P.release_asset_name('server-linux-amd64', 'v0.1.1'),
                         'peerloom-server-v0.1.1-linux-amd64.zip')
        for platform in set(P.PLATFORMS) - {'server-linux-amd64'}:
            self.assertEqual(P.release_asset_name(platform, 'v0.1.1'), f'peerloom-sdk-v0.1.1-{platform}.zip')
        for platform, tag in [('server-other', 'v0.1.1'), ('android', '../v0.1.1'), ('sdk', 'v0.1.1')]:
            with self.assertRaises(P.Rejected):
                P.release_asset_name(platform, tag)

    def test_release_requires_exact_five_roles(self):
        plan = {'approved': True, 'format_version': 1, 'repository': P.REPO,
                'administration_sha': MASTER, 'operation': 'release', 'release_sha': SHA,
                'tag': 'v0.1.1', 'prerelease': False, 'notes': 'notes', 'final_scope_accepted': True,
                'artifacts': {name: {'id': number} for number, name in enumerate(P.PLATFORMS, 1)}}
        admin = A.Admin(None, plan, MASTER)
        admin.fresh_master = lambda: None
        admin.gates = lambda *args: {}
        admin.ancestor = lambda *args: True
        from unittest.mock import patch
        with patch.object(A, "verify_administration_scope"):
            admin.validate()
        duplicate = copy.deepcopy(plan)
        duplicate['artifacts']['server-linux-amd64']['id'] = duplicate['artifacts']['linux-x86_64']['id']
        admin.plan = duplicate
        with self.assertRaisesRegex(P.Rejected, 'DISTINCT_PRODUCT'):
            admin.validate()
        for missing in P.PLATFORMS:
            changed = copy.deepcopy(plan)
            del changed['artifacts'][missing]
            admin.plan = changed
            with self.subTest(missing=missing), self.assertRaisesRegex(P.Rejected, 'ALL_PLATFORM'):
                admin.validate()
        admin.plan = copy.deepcopy(plan)
        admin.plan['artifacts']['server-unknown'] = {}
        with self.assertRaisesRegex(P.Rejected, 'ALL_PLATFORM'):
            admin.validate()

    def test_server_artifact_must_come_from_canonical_ci_run(self):
        class API:
            def call(self, endpoint):
                return {'id': 7, 'expired': False, 'name': P.ARTIFACT_PREFIX['server-linux-amd64'] + SHA,
                        'digest': 'sha256:' + 'a' * 64, 'workflow_run': {'head_sha': SHA, 'id': 9}}
            def download(self, *args):
                raise AssertionError('noncanonical producer cannot download')
        plan = {'release_sha': SHA, 'artifacts': {'server-linux-amd64': {'id': 7, 'sha256': 'a' * 64}}}
        with self.assertRaisesRegex(P.Rejected, 'WRONG_ARTIFACT'):
            A.Admin(API(), plan, MASTER).artifacts(Path('/unused'), {'ci.yml': 8})

    def test_sdk_rejects_server_payload_even_with_full_checksums(self):
        for platform in ('windows-x86_64', 'apple', 'android'):
            files, _ = package(platform)
            files['bin/device-admin'] = b'forbidden server tool'
            with self.subTest(platform=platform), self.assertRaises(P.Rejected):
                self.verify(files, platform)

class PolicyTests(unittest.TestCase):
    def test_unsafe_paths(self):
        for value in ('/a', '../a', 'a/../b', 'a//b', './a', 'C:/x', 'a:x', 'a\\b', 'NUL.txt', 'a/COM1', 'a.', 'a ', 'a\nq'):
            with self.subTest(value=value), self.assertRaises(P.Rejected):
                P.path_name(value)

    def test_collisions(self):
        for names in (('A', 'a'), ('a', 'a/b'), ('a/b', 'a')):
            registry = P.Names()
            registry.add(names[0])
            with self.assertRaises(P.Rejected):
                registry.add(names[1])

    def test_full_manifest(self):
        digest = hashlib.sha256(b'x').hexdigest()
        P.checksum_manifest((digest + '  x\n').encode(), {'x': digest})
        with self.assertRaises(P.Rejected):
            P.checksum_manifest((digest + '  x\n').encode(), {'x': digest, 'extra': digest})

    def test_valid_zip(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'package.zip'
            files, _ = package()
            write_zip(path, files)
            self.assertEqual(P.verify_zip(path, 'windows-x86_64', SHA, '0.1.0')['size'], path.stat().st_size)

    def test_unlisted_extra(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'package.zip'
            files, _ = package()
            write_zip(path, files)
            with zipfile.ZipFile(path, 'a') as z:
                z.writestr('extra', b'x')
            with self.assertRaisesRegex(P.Rejected, 'COVERAGE'):
                P.verify_zip(path, 'windows-x86_64', SHA, '0.1.0')

    def test_symlink_zip(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'package.zip'
            entry = zipfile.ZipInfo('link')
            entry.create_system = 3
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            with zipfile.ZipFile(path, 'w') as z:
                z.writestr(entry, 'target')
            with self.assertRaisesRegex(P.Rejected, 'SPECIAL'):
                P.verify_zip(path, 'windows-x86_64', SHA, '0.1.0')

    def test_wrong_metadata(self):
        files, meta = package()
        for key, value in [('commit', MASTER), ('cargo_features', 'ci-diagnostics'), ('release_evidence_complete', False), ('platform', 'fake')]:
            changed = dict(meta, **{key: value})
            with self.subTest(key=key), self.assertRaises(P.Rejected):
                P.metadata(json.dumps(changed).encode(), 'windows-x86_64', SHA, '0.1.0')

    def test_missing_maven_evidence(self):
        _, meta = package('android')
        del meta['evidence']['maven']
        with self.assertRaises(P.Rejected):
            P.metadata(json.dumps(meta).encode(), 'android', SHA, '0.1.0')

    def test_linux_tar_modes_and_manifest(self):
        files, meta = installation_package('linux-x86_64')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sdk.zip'
            write_zip(path, files)
            P.verify_zip(path, 'linux-x86_64', SHA, '0.1.0')
        files, meta = installation_package('linux-x86_64', {'go-crossbuilds/linux-amd64/device-server': b'wrong'})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sdk.zip'
            write_zip(path, files)
            with self.assertRaisesRegex(P.Rejected, 'UNEXPECTED_INSTALL'):
                P.verify_zip(path, 'linux-x86_64', SHA, '0.1.0')

    def test_tar_link(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as out:
            item = tarfile.TarInfo('link')
            item.type, item.linkname = tarfile.SYMTYPE, '/etc/passwd'
            out.addfile(item)
        stream.seek(0)
        with self.assertRaisesRegex(P.Rejected, 'SPECIAL'):
            P.verify_linux_tar(stream, {}, {})

class DocumentedGapPackageTests(unittest.TestCase):
    def fixture(self):
        files, meta = package()
        (name, version), (checksum, provenance) = next(iter(P.GAPS.KNOWN.items()))
        record = {'ecosystem':'cargo','name':name,'version':version,'purl':f'pkg:cargo/{name}@{version}',
                  'archive_sha256':checksum,'provenance':provenance,'declared_license':'Apache-2.0/MIT',
                  'issues':['LICENSE_TEXT_MISSING'],'files':[]}
        report = {'format_version':1,'evidence_status':'incomplete','issues':[],'packages':[record]}
        status, gaps = P.GAPS.classify(report)
        meta.update(evidence={'cargo_go':status}, release_evidence_complete=False,
                    release_delivery_eligible=True, documented_gaps=gaps)
        files['release-metadata.json'] = json.dumps(meta).encode()
        files['third-party/cargo-go-all-lock-candidates/report.json'] = json.dumps(report).encode()
        return files, meta, report

    def verify(self, files):
        # Model a producer with internally consistent byte manifests so negative
        # cases reach the semantic gap/notice guard rather than stale hashes.
        for prefix in ('third-party/cargo-go-all-lock-candidates/',):
            nested = {name[len(prefix):]: value for name, value in files.items() if name.startswith(prefix) and name != prefix + 'SHA256SUMS'}
            files[prefix + 'SHA256SUMS'] = sums(nested)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'package.zip'
            write_zip(path, files)
            return P.verify_zip(path, 'windows-x86_64', SHA, '0.1.0')

    def test_exact_gap_delivery_is_not_evidence_complete(self):
        files, meta, _ = self.fixture()
        self.verify(files)
        self.assertFalse(meta['release_evidence_complete'])

    def test_metadata_claim_cannot_hide_unknown_gap(self):
        files, _, report = self.fixture()
        report['packages'][0]['issues'] = ['ARCHIVE_MISSING']
        files['third-party/cargo-go-all-lock-candidates/report.json'] = json.dumps(report).encode()
        with self.assertRaisesRegex(P.Rejected, 'UNKNOWN_LICENSE_GAPS'):
            self.verify(files)

    def test_forged_documented_gap_metadata_rejected(self):
        files, meta, _ = self.fixture()
        meta['documented_gaps'][0]['archive_sha256'] = '0'*64
        files['release-metadata.json'] = json.dumps(meta).encode()
        with self.assertRaisesRegex(P.Rejected, 'UNKNOWN_LICENSE_GAPS'):
            self.verify(files)

    def test_report_notice_deletion_rejected_even_if_outer_list_resealed(self):
        files, _ = package()
        del files['third-party/cargo-go-all-lock-candidates/LICENSE']
        with self.assertRaisesRegex(P.Rejected, 'NOTICE_MISSING'):
            self.verify(files)

    def test_incomplete_maven_is_not_cargo_exception(self):
        files, meta, _ = self.fixture()
        meta['evidence']['maven'] = P.GAPS.DOCUMENTED
        files['release-metadata.json'] = json.dumps(meta).encode()
        with self.assertRaisesRegex(P.Rejected, 'INCOMPLETE_EVIDENCE'):
            self.verify(files)

class MavenDocumentedPackageTests(unittest.TestCase):
    prefix = 'third-party/maven-configurations/'
    def fixture(self):
        files, meta = package('android')
        files = {name:data for name,data in files.items() if not name.startswith(self.prefix)}
        proof = Path(__file__).with_name('testdata')/'maven-gap-proof'
        files.update({self.prefix+p.relative_to(proof).as_posix():p.read_bytes() for p in proof.rglob('*') if p.is_file()})
        report = copy.deepcopy(P.MAVEN.PINS['expected_report'])
        status,gaps = P.MAVEN.classify(report)
        self.assertEqual(len(gaps),19)
        meta.update(release_evidence_complete=False,release_delivery_eligible=True,documented_gaps=[],maven_documented_gaps=gaps)
        meta['evidence']['maven']=status
        files['release-metadata.json']=json.dumps(meta).encode()
        files[self.prefix+'report.json']=json.dumps(report).encode()
        files[self.prefix+'sbom.cdx.json']=b'{}'
        return files,meta,report

    def verify(self,files):
        files[self.prefix+'SHA256SUMS']=sums({n[len(self.prefix):]:b for n,b in files.items() if n.startswith(self.prefix) and n!=self.prefix+'SHA256SUMS'})
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'package.zip';write_zip(path,files)
            return P.verify_zip(path,'android',SHA,'0.1.0')

    def test_exact_21_graph_19_gaps_and_actual_pom_notice_bytes(self):
        files,meta,report=self.fixture()
        self.assertEqual(report['evidence_status'],'incomplete')
        self.assertFalse(meta['release_evidence_complete'])
        self.verify(files)

    def test_resealed_unknown_version_binary_issue_or_graph_rejected(self):
        for change in ('version','binary','issue','package','edge','notice'):
            files,meta,report=self.fixture();scope=report['scopes'][0];record=scope['packages'][0]
            if change=='version':record['coordinate']+='-unknown'
            elif change=='binary':record['artifacts'][0]['sha256']='a'*64
            elif change=='issue':record['issues'].append('POM_MISSING')
            elif change=='package':scope['packages'].pop()
            elif change=='edge':scope['edges'].pop()
            else:
                record=next(p for s in report['scopes'] for p in s['packages'] if p['evidence'])
                notice=record['evidence'].pop();files.pop(self.prefix+notice['file'])
            files[self.prefix+'report.json']=json.dumps(report).encode()
            with self.subTest(change=change),self.assertRaises(P.Rejected):self.verify(files)

    def test_resealed_missing_or_changed_pom_or_notice_rejected(self):
        for kind in ('poms/','licenses/'):
            for action in ('delete','tamper'):
                files,meta,report=self.fixture();name=next(n for n in files if n.startswith(self.prefix+kind))
                if action=='delete':files.pop(name)
                else:files[name]+=b'changed'
                with self.subTest(kind=kind,action=action),self.assertRaises(P.Rejected):self.verify(files)

    def test_metadata_cannot_hide_or_fabricate_gap_status(self):
        for change in ('complete','eligible','gaps','status'):
            files,meta,report=self.fixture()
            if change=='complete':meta['release_evidence_complete']=True
            elif change=='eligible':meta['release_delivery_eligible']=False
            elif change=='gaps':meta['maven_documented_gaps']=[]
            else:meta['evidence']['maven']=P.GAPS.COMPLETE
            files['release-metadata.json']=json.dumps(meta).encode()
            with self.subTest(change=change),self.assertRaises(P.Rejected):self.verify(files)


class ApplePackageTests(unittest.TestCase):
    def fixture(self):
        import plistlib
        files, _ = package('apple')
        prefix = 'SwiftPackage/Artifacts/CPeerloom.xcframework/'
        libraries = []
        for platform, variant, archs in [('ios', '', ['arm64']), ('ios', 'simulator', ['arm64', 'x86_64']), ('macos', '', ['arm64', 'x86_64'])]:
            identifier = platform + '-' + (variant or 'device')
            libraries.append({'SupportedPlatform': platform, 'SupportedPlatformVariant': variant,
                              'SupportedArchitectures': archs, 'LibraryIdentifier': identifier,
                              'LibraryPath': 'libdevice_ffi.a', 'HeadersPath': 'Headers'})
            files[prefix + identifier + '/libdevice_ffi.a'] = b'native archive fixture'
            files[prefix + identifier + '/Headers/device_sdk.h'] = b'canonical header'
        files[prefix + 'Info.plist'] = plistlib.dumps({'AvailableLibraries': libraries})
        files['SwiftPackage/Package.swift'] = b'package fixture'
        return files

    def test_apple_all_five_architectures_present(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'apple.zip'
            write_zip(path, self.fixture())
            P.verify_zip(path, 'apple', SHA, '0.1.0')

    def test_apple_missing_native_slice_not_just_plist(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'apple.zip'
            files = self.fixture()
            del files['SwiftPackage/Artifacts/CPeerloom.xcframework/ios-simulator/libdevice_ffi.a']
            write_zip(path, files)
            with self.assertRaisesRegex(P.Rejected, 'SLICE_MISSING'):
                P.verify_zip(path, 'apple', SHA, '0.1.0')

    def test_apple_header_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'apple.zip'
            files = self.fixture()
            files['SwiftPackage/Artifacts/CPeerloom.xcframework/ios-simulator/Headers/device_sdk.h'] = b'wrong'
            write_zip(path, files)
            with self.assertRaisesRegex(P.Rejected, 'HEADER_MISMATCH'):
                P.verify_zip(path, 'apple', SHA, '0.1.0')

class GatesTests(unittest.TestCase):
    def run_fixture(self, workflow='android.yml'):
        run = {'head_sha': SHA, 'event': 'push', 'head_repository': {'full_name': P.REPO},
               'status': 'completed', 'conclusion': 'success', 'path': '.github/workflows/' + workflow}
        jobs = [{'name': name, 'status': 'completed', 'conclusion': 'success', 'steps': [{'conclusion': 'success'}]} for name in P.WORKFLOWS[workflow]]
        return run, jobs

    def test_all_canonical_jobs(self):
        for workflow in P.WORKFLOWS:
            run, jobs = self.run_fixture(workflow)
            P.verify_run(run, jobs, workflow, SHA)
            with self.assertRaises(P.Rejected):
                P.verify_run(run, jobs[:-1], workflow, SHA)

    def test_capacity_job_is_mandatory_for_product_release(self):
        run, jobs = self.run_fixture('ci.yml')
        self.assertEqual(P.WORKFLOWS['ci.yml'], {'verify', 'capacity-500'})
        P.verify_run(run, jobs, 'ci.yml', SHA)
        for conclusion in ('missing', 'failure', 'skipped'):
            changed = [dict(job) for job in jobs if job['name'] != 'capacity-500']
            if conclusion != 'missing':
                changed.append({'name': 'capacity-500', 'status': 'completed',
                                'conclusion': conclusion, 'steps': [{'conclusion': conclusion}]})
            with self.subTest(conclusion=conclusion), self.assertRaises(P.Rejected):
                P.verify_run(run, changed, 'ci.yml', SHA)

    def test_wrong_head_event_repo_status(self):
        run, jobs = self.run_fixture()
        for key, value in [('head_sha', MASTER), ('event', 'pull_request'), ('conclusion', 'failure'), ('head_repository', {'full_name': 'fork/repo'})]:
            with self.subTest(key=key), self.assertRaises(P.Rejected):
                P.verify_run(dict(run, **{key: value}), jobs, 'android.yml', SHA)

    def test_skipped_step(self):
        run, jobs = self.run_fixture()
        jobs[0]['steps'][0]['conclusion'] = 'skipped'
        with self.assertRaises(P.Rejected):
            P.verify_run(run, jobs, 'android.yml', SHA)

    def test_event_boundary(self):
        env = {'GITHUB_EVENT_NAME': 'push', 'GITHUB_REPOSITORY': P.REPO, 'GITHUB_REF': 'refs/heads/master', 'GITHUB_SHA': MASTER}
        event = {'repository': {'full_name': P.REPO}, 'ref': 'refs/heads/master', 'before': SHA, 'after': MASTER,
                 'commits': [{'id': MASTER}]}  # Real Actions shape: no file arrays.
        A.context(env, event, {'administration_sha': 'event', 'operation': 'release'})
        for key, value in [('GITHUB_EVENT_NAME', 'pull_request_target'), ('GITHUB_REF', 'refs/heads/feat/test'), ('GITHUB_REPOSITORY', 'fork/repo')]:
            with self.subTest(key=key), self.assertRaises(P.Rejected):
                A.context(dict(env, **{key: value}), event, {'administration_sha': 'event', 'operation': 'release'})
        for change in ({'created': True}, {'forced': True}, {'deleted': True}, {'before': 'bad'}, {'before': '0' * 40}):
            with self.subTest(change=change), self.assertRaises(P.Rejected):
                A.context(env, dict(event, **change), {'administration_sha': 'event', 'operation': 'release'})

class PushComparisonTests(unittest.TestCase):
    def comparison(self):
        return {'base_commit': {'sha': SHA}, 'merge_base_commit': {'sha': SHA},
                'status': 'ahead', 'ahead_by': 2, 'behind_by': 0, 'total_commits': 2,
                'files': [{'filename': 'release/approved-plan.json', 'status': 'modified'}]}

    def call(self, value, event=None):
        from unittest.mock import Mock
        api = Mock()
        api.call.return_value = value
        A.verify_plan_changed(api, event or {'before': SHA, 'after': MASTER, 'commits': [{'id': MASTER}]}, MASTER)
        api.call.assert_called_once_with('/repos/' + P.REPO + '/compare/' + SHA + '...' + MASTER + '?per_page=100&page=1')

    def test_real_actions_no_commit_file_arrays_uses_fixed_compare(self):
        self.call(self.comparison())

    def test_wrong_ancestor_or_non_fast_forward_rejected(self):
        for change in ({'merge_base_commit': {'sha': TREE}}, {'base_commit': {'sha': TREE}},
                       {'status': 'diverged'}, {'status': 'identical'}, {'behind_by': 1}, {'total_commits': 999}):
            with self.subTest(change=change), self.assertRaises(P.Rejected):
                self.call(dict(self.comparison(), **change))

    def test_absent_renamed_removed_plan_rejected(self):
        for files in ([{'filename': 'other', 'status': 'modified'}],
                      [{'filename': 'release/approved-plan.json', 'status': 'removed'}],
                      [{'filename': 'release/approved-plan.json', 'status': 'renamed', 'previous_filename': 'other'}]):
            with self.subTest(files=files), self.assertRaises(P.Rejected):
                self.call(dict(self.comparison(), files=files))

    def test_truncated_or_duplicate_file_inventory_rejected(self):
        for files in (None, [], self.comparison()['files'] * 2,
                      self.comparison()['files'] + [{'filename': f'file-{i}', 'status': 'added'} for i in range(299)]):
            with self.subTest(count=None if files is None else len(files)), self.assertRaises(P.Rejected):
                self.call(dict(self.comparison(), files=files))

    def test_event_supplied_compare_url_never_used(self):
        self.call(self.comparison(), {'before': SHA, 'after': MASTER,
                                      'compare': 'https://untrusted.invalid/collect'})

class AdministrationScopeTests(unittest.TestCase):
    def test_exact_documentation_and_plan_only(self):
        for name in P.ADMINISTRATION_FILES:
            P.verify_administration_files([{'filename': name, 'status': 'modified'}])

    def test_product_and_execution_changes_rejected(self):
        for name in ('src/device-sdk/Cargo.lock', 'src/device-server/main.go',
                     '.github/workflows/native.yml', '.github/workflows/release-admin.yml',
                     'scripts/release-admin.py', 'scripts/release-policy.py',
                     'docs/unknown.md', 'release/other.json', 'README.md/../src/main.rs'):
            with self.subTest(name=name), self.assertRaisesRegex(P.Rejected, 'SCOPE'):
                P.verify_administration_files([
                    {'filename': 'README.md', 'status': 'modified'},
                    {'filename': name, 'status': 'modified'},
                ])

    def test_rename_delete_duplicate_truncation_fail_closed(self):
        for files in (
            [{'filename': 'README.md', 'status': 'removed'}],
            [{'filename': 'README.md', 'status': 'modified', 'previous_filename': 'src/main.rs'}],
            [{'filename': 'README.md', 'status': 'modified'}] * 2,
            [{'filename': str(i), 'status': 'added'} for i in range(300)], [], [None],
        ):
            with self.subTest(files=files), self.assertRaises(P.Rejected):
                P.verify_administration_files(files)

    def test_complete_source_range_not_just_last_push(self):
        from unittest.mock import Mock
        value = PushComparisonTests().comparison()
        value['files'].append({'filename': 'src/device-sdk/Cargo.lock', 'status': 'modified'})
        api = Mock()
        api.call.return_value = value
        with self.assertRaisesRegex(P.Rejected, 'SCOPE'):
            A.verify_administration_scope(api, SHA, MASTER)
        api.call.assert_called_once_with('/repos/' + P.REPO + '/compare/' + SHA + '...' + MASTER + '?per_page=100&page=1')

    def test_source_gates_remain_but_admin_gates_are_not_repeated(self):
        from unittest.mock import Mock, patch
        plan = {'approved': True, 'format_version': 1, 'repository': P.REPO,
                'administration_sha': MASTER, 'operation': 'release', 'release_sha': SHA, 'tag_sha': MASTER,
                'tag': 'v0.1.1', 'prerelease': False, 'notes': 'notes', 'final_scope_accepted': True,
                'artifacts': {name: {'id': number} for number, name in enumerate(P.PLATFORMS, 1)}}
        admin = A.Admin(Mock(), plan, MASTER)
        admin.fresh_master = Mock()
        admin.ancestor = Mock(return_value=True)
        admin.gates = Mock(return_value={'ci.yml': 123})
        with patch.object(A, 'verify_administration_scope') as scope:
            self.assertEqual(admin.validate(), {'ci.yml': 123})
            scope.assert_called_once_with(admin.api, SHA, MASTER, 'v0.1.1')
        admin.gates.assert_called_once_with(SHA)


class ReviewedBootstrapTests(unittest.TestCase):
    def setup_scope(self):
        from unittest.mock import Mock
        files = [
            {'filename': 'release/approved-plan.json', 'status': 'modified'},
            {'filename': A.EXECUTION_FILE, 'status': 'modified', 'sha': TREE},
            {'filename': '.github/workflows/native.yml', 'status': 'modified', 'sha': MASTER},
        ]
        value = PushComparisonTests().comparison()
        value['base_commit']['sha'] = A.BOOTSTRAP_SOURCE
        value['merge_base_commit']['sha'] = A.BOOTSTRAP_SOURCE
        value['files'] = files
        api = Mock()
        api.call.side_effect = [value, {'type': 'file', 'sha': SHA}]
        blobs = {'.github/workflows/native.yml': {'before_blob': SHA, 'after_blob': MASTER}}
        return api, value, blobs

    def test_only_reviewed_exact_transition_bytes(self):
        from unittest.mock import patch
        api, _, blobs = self.setup_scope()
        with patch.object(A, 'REVIEWED_BOOTSTRAP_BLOBS', blobs):
            A.verify_administration_scope(api, A.BOOTSTRAP_SOURCE, TREE, A.BOOTSTRAP_TAG)
        self.assertIn('?ref=' + A.BOOTSTRAP_SOURCE, api.call.call_args.args[0])

    def test_bootstrap_is_only_this_reviewed_source_and_seven_blob_files(self):
        self.assertEqual(A.BOOTSTRAP_SOURCE, '25b33273ac5bbd03506905a635b1453dcf969c70')
        self.assertEqual(A.BOOTSTRAP_TAG, 'v0.1.3')
        self.assertEqual(set(A.REVIEWED_BOOTSTRAP_BLOBS), {
            '.github/workflows/release-admin.yml', 'scripts/test-release-admin.py',
            'scripts/test-workflow-triggers.py', '.github/workflows/ci.yml',
            '.github/workflows/native.yml', '.github/workflows/android.yml',
            '.github/workflows/admin-web.yml'})
        # 历史审核记录固定到 v0.1.3 管理提交 0b0d2962cd36338e1a92f3321c60d26ede1fdb51。
        # 不与后续工作树比较，也不授予新版本复用历史豁免的权限。
        expected = {
            '.github/workflows/admin-web.yml': {
                'before_blob': 'd40bf6215a290591b70eed10d017ca271743ae2f',
                'after_blob': 'bf4322315b6b40e6fd6c0343ab6f6ddd30b3c5d5',
            },
            '.github/workflows/android.yml': {
                'before_blob': 'e3c94bcdfa515493f03f5bf6574c0995dcf1cadf',
                'after_blob': '37fe5630031ec6cca8fe38412703d020d3642f82',
            },
            '.github/workflows/ci.yml': {
                'before_blob': 'd34a919877b3793cdc3aecd8236de67d79f28f08',
                'after_blob': 'cae53369b209e223d6b5b2201838d3d81021b1ec',
            },
            '.github/workflows/native.yml': {
                'before_blob': '9680d45597f958bdb96efd55c4aa620109b75283',
                'after_blob': '4a14e8b01e0e652b1efcee28f623b2675ab01f8f',
            },
            '.github/workflows/release-admin.yml': {
                'before_blob': '637fe5be5913635194e74bf5c409f973d3e5911d',
                'after_blob': 'a1eb0ef4944aedd1f93c80a8ade123404fd6c5b9',
            },
            'scripts/test-release-admin.py': {
                'before_blob': 'ebf16849622b523020e97ff786db2b6b64a34858',
                'after_blob': '0ee4d5d762f483cd905a0470939c0dfbfa01255c',
            },
            'scripts/test-workflow-triggers.py': {
                'before_blob': '0d313f72f1e76b4afc57317c1f2eae299c399533',
                'after_blob': 'dfc6913d29c6ca264ab555c45d77e197d096e374',
            },
        }
        self.assertEqual(A.REVIEWED_BOOTSTRAP_BLOBS, expected)
        self.assertEqual(P.ADMINISTRATION_FILES, {
            'README.md', 'docs/assets/peerloom-banner.svg', 'release/approved-plan.json'})

    def test_real_historical_inventory_rejects_later_workflow_blob(self):
        from unittest.mock import Mock
        value = PushComparisonTests().comparison()
        value['base_commit']['sha'] = A.BOOTSTRAP_SOURCE
        value['merge_base_commit']['sha'] = A.BOOTSTRAP_SOURCE
        value['files'] += [
            {'filename': A.EXECUTION_FILE, 'status': 'modified', 'sha': TREE},
            *({'filename': name, 'status': 'modified', 'sha': entry['after_blob']}
              for name, entry in A.REVIEWED_BOOTSTRAP_BLOBS.items()),
        ]
        previous = [{'type': 'file', 'sha': entry['before_blob']}
                    for entry in A.REVIEWED_BOOTSTRAP_BLOBS.values()]
        api = Mock()
        api.call.side_effect = [value, *previous]
        A.verify_administration_scope(api, A.BOOTSTRAP_SOURCE, TREE, A.BOOTSTRAP_TAG)
        changed = copy.deepcopy(value)
        for entry in changed['files']:
            if entry['filename'] == '.github/workflows/android.yml':
                # 宿主关闭修复分支的真实新 blob 不能冒充 v0.1.3 历史审核字节。
                entry['sha'] = '0b11409a3e7df4662b8712a4dd53d903b7740375'
        api.call.side_effect = [changed, *previous]
        with self.assertRaisesRegex(P.Rejected, 'BOOTSTRAP_FILE_BLOB_MISMATCH'):
            A.verify_administration_scope(api, A.BOOTSTRAP_SOURCE, TREE, A.BOOTSTRAP_TAG)

    def test_wrong_source_tag_after_or_before_rejected(self):
        from unittest.mock import patch
        for kind in ('source', 'tag', 'after', 'before', 'extra', 'removed', 'rename', 'missing'):
            api, value, blobs = self.setup_scope()
            source, tag = A.BOOTSTRAP_SOURCE, A.BOOTSTRAP_TAG
            previous = {'type': 'file', 'sha': SHA}
            if kind == 'source':
                source = SHA
                value['base_commit']['sha'] = value['merge_base_commit']['sha'] = source
            elif kind == 'tag':
                tag = 'v0.1.2'
            elif kind == 'after':
                value['files'][-1]['sha'] = SHA
            elif kind == 'before':
                previous['sha'] = TREE
            elif kind == 'extra':
                value['files'].append({'filename': 'src/main.rs', 'status': 'added', 'sha': TREE})
            elif kind == 'removed':
                value['files'][-1]['status'] = 'removed'
            elif kind == 'rename':
                value['files'][-1]['previous_filename'] = 'other'
            elif kind == 'missing':
                value['files'].pop()
            api.call.side_effect = [value, previous]
            with self.subTest(kind=kind), patch.object(A, 'REVIEWED_BOOTSTRAP_BLOBS', blobs), self.assertRaises(P.Rejected):
                A.verify_administration_scope(api, source, TREE, tag)


class ReadOnlyCandidateTests(unittest.TestCase):
    def event(self):
        env = {'GITHUB_EVENT_NAME': 'push', 'GITHUB_REPOSITORY': P.REPO,
               'GITHUB_REF': 'refs/heads/feat/capacity-unlimited', 'GITHUB_SHA': MASTER}
        event = {'repository': {'full_name': P.REPO}, 'ref': env['GITHUB_REF'],
                 'before': SHA, 'after': MASTER}
        return env, event, {'approved': True, 'administration_sha': 'event', 'operation': 'release'}

    def test_only_nonempty_feat_push_is_accepted(self):
        env, event, plan = self.event()
        for ref in ('refs/heads/feat/capacity-unlimited', 'refs/heads/feat/release/v0.1.3'):
            self.assertEqual(A.candidate_context(dict(env, GITHUB_REF=ref), dict(event, ref=ref), plan)[1], MASTER)
        for key, value in [('GITHUB_REF', 'refs/heads/master'), ('GITHUB_REF', 'refs/heads/other'),
                           ('GITHUB_REF', 'refs/heads/feat/'), ('GITHUB_REF', 'refs/heads/feature/release'),
                           ('GITHUB_REF', 'refs/heads/feat/../master'), ('GITHUB_REF', 'refs/heads/feat//release'),
                           ('GITHUB_EVENT_NAME', 'pull_request'),
                           ('GITHUB_EVENT_NAME', 'workflow_dispatch'), ('GITHUB_REPOSITORY', 'fork/repo')]:
            with self.subTest(key=key, value=value), self.assertRaises(P.Rejected):
                A.candidate_context(dict(env, **{key: value}),
                                    dict(event, ref=value) if key == 'GITHUB_REF' else event, plan)
        for delta in ({'after': SHA}, {'forced': True}, {'deleted': True}, {'created': True},
                      {'repository': {'full_name': 'fork/repo'}}, {'before': '0' * 40}):
            with self.subTest(delta=delta), self.assertRaises(P.Rejected):
                A.candidate_context(env, dict(event, **delta), plan)
        for invalid in ('not-a-sha', 'F' * 40, ''):
            with self.assertRaises(P.Rejected):
                A.candidate_context(dict(env, GITHUB_SHA=invalid), dict(event, after=invalid), plan)
        with self.assertRaises(P.Rejected):
            A.context(env, event, plan)

    def test_candidate_cannot_execute_even_before_reading_plan(self):
        from unittest.mock import patch
        with patch.object(A.sys, 'argv', ['release-admin.py', '--validate-candidate', '--execute']), \
             patch.object(A.Path, 'read_text') as read, self.assertRaisesRegex(P.Rejected, 'CANDIDATE_WRITE'):
            A.main()
        read.assert_not_called()

    def test_candidate_validates_artifacts_without_publish_or_enabled_output(self):
        from unittest.mock import Mock, patch
        env, event, plan = self.event()
        env['GITHUB_EVENT_PATH'] = '/unused-event'
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'output'
            env['GITHUB_OUTPUT'] = str(output)
            admin = Mock()
            admin.validate.return_value = {'ci.yml': 1}
            with patch.dict(A.os.environ, env, clear=True), \
                 patch.object(A.sys, 'argv', ['release-admin.py', '--validate-candidate']), \
                 patch.object(A.Path, 'read_text', side_effect=[json.dumps(plan), json.dumps(event)]), \
                 patch.object(A.subprocess, 'check_output', return_value=MASTER), \
                 patch.object(A.subprocess, 'run', return_value=Mock(returncode=0)), \
                 patch.object(A, 'GitHub'), patch.object(A, 'Admin', return_value=admin), \
                 patch.object(A, 'verify_plan_changed') as changed:
                A.main()
            admin.validate.assert_called_once()
            admin.artifacts.assert_called_once()
            admin.publish.assert_not_called()
            changed.assert_not_called()
            self.assertEqual(output.read_text(), 'enabled=false\n')

    def test_candidate_fresh_ref_and_both_ancestry_links_are_enforced(self):
        from unittest.mock import Mock, patch
        for case in ('valid', 'valid_second_branch', 'moved', 'source_not_retained', 'master_not_ancestor'):
            env, event, plan = self.event()
            if case == 'valid_second_branch':
                env['GITHUB_REF'] = event['ref'] = 'refs/heads/feat/release/v0.1.3'
            plan['release_sha'] = SHA
            env['GITHUB_EVENT_PATH'] = '/unused-event'
            api = Mock()
            api.call.side_effect = [{'object': {'sha': TREE if case == 'moved' else MASTER}},
                                    {'object': {'sha': SHA}}]
            admin = Mock()
            admin.ancestor.side_effect = [case != 'source_not_retained', case != 'master_not_ancestor']
            admin.validate.side_effect = lambda: (admin.fresh_master() or {'ci.yml': 1})
            with self.subTest(case=case), patch.dict(A.os.environ, env, clear=True), \
                 patch.object(A.sys, 'argv', ['release-admin.py', '--validate-candidate']), \
                 patch.object(A.Path, 'read_text', side_effect=[json.dumps(plan), json.dumps(event)]), \
                 patch.object(A.subprocess, 'check_output', return_value=MASTER), \
                 patch.object(A.subprocess, 'run', return_value=Mock(returncode=0)), \
                 patch.object(A, 'GitHub', return_value=api), patch.object(A, 'Admin', return_value=admin):
                if case in ('valid', 'valid_second_branch'):
                    A.main()
                    admin.artifacts.assert_called_once()
                    self.assertEqual(api.call.call_args_list[0].args[0],
                                     '/repos/' + P.REPO + '/git/ref/' + event['ref'].removeprefix('refs/'))
                    self.assertTrue(all(len(call.args) == 1 and not call.kwargs for call in api.call.call_args_list))
                else:
                    with self.assertRaises(P.Rejected):
                        A.main()
                    admin.artifacts.assert_not_called()
                admin.publish.assert_not_called()


class ReleaseOnlyBoundaryTests(unittest.TestCase):
    def test_removed_branch_deletion_interfaces(self):
        self.assertFalse(hasattr(A.Admin, 'cleanup'))
        self.assertFalse(hasattr(A, 'execute_delete'))
        for name in ('TASK_BRANCHES', 'validate_cleanup', 'deletion_command'):
            self.assertFalse(hasattr(P, name))
        source = Path(A.__file__).read_text(encoding='utf-8')
        self.assertNotIn('GIT_ASKPASS', source)
        self.assertNotIn('--force-with-lease', source)

    def test_delete_method_is_not_an_api_capability(self):
        from unittest.mock import patch
        with patch.object(A.subprocess, 'run') as process:
            with self.assertRaisesRegex(P.Rejected, 'METHOD_FORBIDDEN'):
                A.GitHub().call('/repos/' + P.REPO + '/git/refs/heads/anything', method='DELETE')
            process.assert_not_called()

    def test_approved_cleanup_rejected_before_any_api(self):
        plan = {'approved': True, 'format_version': 1, 'repository': P.REPO,
                'administration_sha': MASTER, 'operation': 'cleanup', 'branches': []}
        with self.assertRaisesRegex(P.Rejected, 'RELEASE_OPERATION'):
            A.Admin(None, plan, MASTER).validate()

    def test_only_administration_event_binding_survives(self):
        env = {'GITHUB_EVENT_NAME': 'push', 'GITHUB_REPOSITORY': P.REPO,
               'GITHUB_REF': 'refs/heads/master', 'GITHUB_SHA': MASTER}
        event = {'repository': {'full_name': P.REPO}, 'ref': 'refs/heads/master', 'before': SHA, 'after': MASTER}
        plan = {'administration_sha': 'event', 'operation': 'release'}
        bound, commit = A.context(env, event, plan)
        self.assertEqual(bound['administration_sha'], MASTER)
        self.assertEqual(plan['administration_sha'], 'event')
        for change in ({'operation': 'cleanup'}, {'branches': []},
                       {'branches': [{'sha': 'event'}]}, {'release_sha': 'event'},
                       {'artifacts': {'android': {'source': 'event'}}}):
            with self.subTest(change=change), self.assertRaises(P.Rejected):
                A.context(env, event, dict(plan, **change))


class ReleaseTests(unittest.TestCase):
    def setup_admin(self):
        plan = {'tag': 'v0.1.0', 'notes': 'approved notes', 'prerelease': True, 'release_sha': SHA}
        release = {'id': 12, 'tag_name': 'v0.1.0', 'body': 'approved notes', 'prerelease': True, 'draft': True,
                   'assets': [{'name': 'package.zip', 'size': 3, 'digest': 'sha256:' + 'a' * 64, 'state': 'uploaded'}]}
        outputs = {'package.zip': (Path('/unused'), {'size': 3, 'sha256': 'a' * 64})}
        class API:
            def __init__(self):
                self.release, self.writes = copy.deepcopy(release), []
            def call(self, endpoint, method='GET', data=None, **kw):
                if method != 'GET':
                    self.writes.append((endpoint, method, data))
                if '/git/ref/heads/master' in endpoint:
                    return {'object': {'sha': MASTER}}
                if '/git/ref/tags/' in endpoint:
                    return {'object': {'type': 'commit', 'sha': SHA}}
                if method == 'PATCH':
                    self.release['draft'] = False
                return copy.deepcopy(self.release)
        api = API()
        return A.Admin(api, plan, MASTER), api, outputs

    def test_publish_then_idempotent(self):
        admin, api, outputs = self.setup_admin()
        admin.publish(outputs)
        self.assertEqual(len(api.writes), 1)
        admin.publish(outputs)
        self.assertEqual(len(api.writes), 1)

    def test_concurrent_metadata_changes_before_publish(self):
        for key, value in [('id', 99), ('body', 'changed'), ('prerelease', False), ('tag_name', 'v9.9.9')]:
            admin, api, outputs = self.setup_admin()
            original = api.call
            def changed(endpoint, method='GET', data=None, **kw):
                result = original(endpoint, method, data, **kw)
                if endpoint.endswith('/releases/12') and method == 'GET':
                    result[key] = value
                return result
            api.call = changed
            with self.subTest(key=key), self.assertRaises(P.Rejected):
                admin.publish(outputs)
            self.assertFalse(api.writes)

    def test_published_mismatch_not_overwritten(self):
        admin, api, outputs = self.setup_admin()
        api.release['draft'] = False
        api.release['body'] = 'concurrent changed notes'
        with self.assertRaises(P.Rejected):
            admin.publish(outputs)
        self.assertFalse(api.writes)

    def test_wrong_tag_stops(self):
        admin, api, outputs = self.setup_admin()
        original = api.call
        def changed(endpoint, **kw):
            if '/git/ref/tags/' in endpoint:
                return {'object': {'type': 'commit', 'sha': MASTER}}
            return original(endpoint, **kw)
        api.call = changed
        with self.assertRaisesRegex(P.Rejected, 'TAG_MISMATCH'):
            admin.publish(outputs)
        self.assertFalse(api.writes)

    def test_bad_asset_digest(self):
        admin, api, outputs = self.setup_admin()
        api.release['assets'][0]['digest'] = 'sha256:' + 'b' * 64
        with self.assertRaises(P.Rejected):
            admin.publish(outputs)
        self.assertFalse(api.writes)

    def test_checked_in_plan_structure(self):
        # Approval is a reviewed plan state, not an invariant of the source tree.
        plan = json.loads((Path(__file__).resolve().parents[1] / 'release/approved-plan.json').read_text(encoding='utf-8'))
        self.assertIsInstance(plan, dict)
        self.assertEqual(plan['format_version'], 1)
        self.assertEqual(plan['repository'], P.REPO)
        self.assertIs(type(plan['approved']), bool)
        self.assertEqual(plan['administration_sha'], 'event')
        self.assertEqual(plan['operation'], 'release')
        self.assertNotIn('branches', plan)
        if plan['approved']:
            P.sha(plan['release_sha'])
            self.assertRegex(plan['tag'], r'^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$')
            self.assertIs(type(plan['prerelease']), bool)
            self.assertIsInstance(plan['notes'], str)
            self.assertTrue(plan['notes'])
            self.assertIs(plan['final_scope_accepted'], True)
            self.assertEqual(set(plan['artifacts']), set(P.PLATFORMS))

class ExplicitAdministrationTagTests(unittest.TestCase):
    def test_only_explicit_event_target_binds_without_changing_artifact_source(self):
        env = {'GITHUB_EVENT_NAME': 'push', 'GITHUB_REPOSITORY': P.REPO,
               'GITHUB_REF': 'refs/heads/master', 'GITHUB_SHA': MASTER}
        event = {'repository': {'full_name': P.REPO}, 'ref': env['GITHUB_REF'], 'before': SHA, 'after': MASTER}
        plan = {'administration_sha': 'event', 'tag_sha': 'event', 'operation': 'release',
                'release_sha': SHA, 'artifacts': {'android': {'id': 123, 'sha256': 'a' * 64}}}
        original = copy.deepcopy(plan)
        bound, commit = A.context(env, event, plan)
        self.assertEqual(bound['tag_sha'], MASTER)
        self.assertEqual(commit, MASTER)
        self.assertEqual(bound['release_sha'], SHA)
        self.assertEqual(bound['artifacts'], original['artifacts'])
        self.assertEqual(plan, original)
        for value in (None, SHA, MASTER, 'master', 'latest', ''):
            with self.subTest(value=value), self.assertRaisesRegex(P.Rejected, 'TAG_EVENT'):
                A.context(env, event, dict(plan, tag_sha=value))
        with self.assertRaisesRegex(P.Rejected, 'EVENT_OUTSIDE'):
            A.context(env, event, dict(plan, artifacts={'android': {'sha256': 'event'}}))

    def test_old_default_and_explicit_new_tag_creation(self):
        from unittest.mock import Mock
        for explicit, expected in ((False, SHA), (True, MASTER)):
            api = Mock()
            api.call.side_effect = [None, {}, {'object': {'type': 'commit', 'sha': expected}}]
            plan = {'tag': 'v0.1.1', 'release_sha': SHA}
            if explicit:
                plan['tag_sha'] = MASTER
            admin = A.Admin(api, plan, MASTER)
            admin.tag(create=True)
            self.assertEqual(api.call.call_args_list[1].args,
                             ('/repos/' + P.REPO + '/git/refs', 'POST',
                              {'ref': 'refs/tags/v0.1.1', 'sha': expected}))

    def test_existing_wrong_tag_is_never_moved_or_overwritten(self):
        from unittest.mock import Mock
        api = Mock()
        api.call.return_value = {'object': {'type': 'commit', 'sha': SHA}}
        admin = A.Admin(api, {'tag': 'v0.1.1', 'release_sha': SHA, 'tag_sha': MASTER}, MASTER)
        with self.assertRaisesRegex(P.Rejected, 'TAG_MISMATCH'):
            admin.tag(create=True)
        api.call.assert_called_once_with('/repos/' + P.REPO + '/git/ref/tags/v0.1.1', missing=True)
        api.reset_mock()
        admin.plan['tag_sha'] = TREE
        with self.assertRaisesRegex(P.Rejected, 'TAG_TARGET'):
            admin.tag(create=True)
        api.call.assert_not_called()

    def test_release_target_is_explicit_tag_commit_not_artifact_source(self):
        from unittest.mock import Mock
        api = Mock()
        plan = {'tag': 'v0.1.1', 'release_sha': SHA, 'tag_sha': MASTER, 'notes': 'explicit provenance', 'prerelease': False}
        draft = {'id': 12, 'tag_name': plan['tag'], 'body': plan['notes'], 'prerelease': False, 'draft': True, 'assets': []}
        api.call.side_effect = [None, draft, draft, {}, dict(draft, draft=False)]
        admin = A.Admin(api, plan, MASTER)
        admin.fresh_master = Mock()
        admin.tag = Mock(return_value={'object': {'sha': MASTER}})
        admin.publish({})
        create = api.call.call_args_list[1]
        self.assertEqual(create.args[2]['target_commitish'], MASTER)
        self.assertEqual(admin.plan['release_sha'], SHA)

    def test_candidate_binds_same_event_but_cannot_execute(self):
        env, event, plan = ReadOnlyCandidateTests().event()
        plan['tag_sha'] = 'event'
        bound, commit = A.candidate_context(env, event, plan)
        self.assertEqual(bound['tag_sha'], commit)
        ReadOnlyCandidateTests().test_candidate_cannot_execute_even_before_reading_plan()


class RedactedApiFailureTests(unittest.TestCase):
    def failure(self, suffix, method='GET', stderr='gh: private response (HTTP 403)'):
        from unittest.mock import Mock, patch
        response = Mock(returncode=1, stdout='secret-response-body', stderr=stderr)
        with patch.object(A.subprocess, 'run', return_value=response) as process:
            with self.assertRaises(P.Rejected) as raised:
                A.GitHub().call('/repos/' + P.REPO + suffix, method, {'secret': 'request-secret'})
        self.assertEqual(process.call_count, 1)  # Diagnostic only; no retry.
        message = str(raised.exception)
        for secret in ('private response', 'secret-response-body', 'request-secret', suffix, 'token-value'):
            self.assertNotIn(secret, message)
        return message

    def test_fixed_operations_and_numeric_status_only(self):
        for path, method, category in (
            ('/git/refs', 'POST', 'create_git_ref'),
            ('/releases', 'POST', 'create_release'),
            ('/releases/123', 'PATCH', 'update_release'),
            ('/git/ref/tags/private-tag', 'GET', 'read_git_ref'),
            ('/actions/artifacts/123', 'GET', 'read_artifact'),
            ('/actions/runs/123', 'GET', 'read_workflow'),
            ('/compare/private...private', 'GET', 'read_compare'),
            ('/contents/private-file', 'GET', 'read_contents'),
            ('/releases/tags/private-tag', 'GET', 'read_release'),
            ('/unknown/private', 'GET', 'other'),
        ):
            with self.subTest(path=path, method=method):
                self.assertEqual(self.failure(path, method),
                                 f'GITHUB_API_FAILED operation={category} method={method} http_status=403')

    def test_missing_or_ambiguous_status_is_zero_without_raw_error(self):
        for stderr in ('token-value authentication failed', 'private (HTTP 403) and (HTTP 422)',
                       '(HTTP token-value)', '(HTTP 999)', '(HTTP 4030)'):
            with self.subTest(stderr=stderr):
                self.assertTrue(self.failure('/git/refs', 'POST', stderr).endswith('http_status=0'))

    def test_expected_missing_404_behavior_is_unchanged(self):
        from unittest.mock import Mock, patch
        with patch.object(A.subprocess, 'run', return_value=Mock(returncode=1, stdout='private', stderr='private (HTTP 404)')):
            self.assertIsNone(A.GitHub().call('/repos/' + P.REPO + '/git/ref/tags/missing', missing=True))
        self.assertTrue(self.failure('/git/ref/tags/missing', stderr='private (HTTP 404)').endswith('http_status=404'))


class ExtraBoundaryTests(unittest.TestCase):
    def test_workflow_permission_isolation(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / '.github/workflows/release-admin.yml').read_text()
        self.assertIn("on:\n  push:\n    branches: [master, 'feat/**']\n    paths:\n", source)
        path_block = source.split('    paths:\n', 1)[1].split('permissions:', 1)[0]
        self.assertEqual(set(line.strip().removeprefix('- ') for line in path_block.splitlines() if line.strip()), {
            'release/approved-plan.json', 'scripts/release-admin.py', 'scripts/release-policy.py',
            'scripts/test-release-admin.py', 'scripts/test-workflow-triggers.py',
            '.github/workflows/release-admin.yml', '.github/workflows/ci.yml',
            '.github/workflows/native.yml', '.github/workflows/android.yml', '.github/workflows/admin-web.yml',
        })
        self.assertNotIn('pull_request', source)
        self.assertNotIn('workflow_dispatch', source)
        self.assertEqual(source.count('contents: write'), 1)
        read_job, write_job = source.split('  apply-approved-plan:', 1)
        self.assertNotIn('contents: write', read_job)
        self.assertNotIn('--execute', read_job)
        self.assertIn('--validate-candidate', read_job)
        self.assertIn('run: python3 -S scripts/test-release-admin.py', read_job)
        self.assertIn("needs.preflight.outputs.enabled == 'true'", write_job)
        self.assertIn("github.ref == 'refs/heads/master'", write_job)
        self.assertIn('permissions:\n      contents: write\n      actions: read', write_job)
        self.assertEqual(source.count('persist-credentials: false'), 2)
        self.assertEqual(source.count('ref: ${{ github.sha }}'), 2)

    def test_plan_false_never_calls_api(self):
        from unittest.mock import patch
        plan = {'format_version': 1, 'repository': P.REPO, 'approved': False,
                'administration_sha': 'event', 'operation': 'release'}
        with patch.dict(A.os.environ, {}, clear=True), \
                patch.object(Path, 'read_text', return_value=json.dumps(plan)) as read, \
                patch.object(A, 'GitHub', side_effect=AssertionError('must remain offline')) as api, \
                patch('sys.argv', ['release-admin.py', '--execute']):
            A.main()
        read.assert_called_once()
        api.assert_not_called()

    def test_approved_plan_untrusted_event_never_calls_api(self):
        from unittest.mock import patch
        plan = {'format_version': 1, 'repository': P.REPO, 'approved': True,
                'administration_sha': 'event', 'operation': 'release'}
        env = {'GITHUB_EVENT_NAME': 'pull_request', 'GITHUB_EVENT_PATH': '/fixture/event.json'}
        with patch.dict(A.os.environ, env, clear=True), \
                patch.object(Path, 'read_text', side_effect=[json.dumps(plan), '{}']), \
                patch.object(A, 'GitHub', side_effect=AssertionError('must remain offline')) as api, \
                patch.object(A.subprocess, 'check_output') as git, \
                patch('sys.argv', ['release-admin.py', '--execute']), \
                self.assertRaisesRegex(P.Rejected, 'UNTRUSTED_EVENT'):
            A.main()
        api.assert_not_called()
        git.assert_not_called()

    def test_new_maven_policy_and_pin_are_trusted_checkout_inputs(self):
        from unittest.mock import patch, Mock
        env={'GITHUB_EVENT_NAME':'push','GITHUB_REPOSITORY':P.REPO,'GITHUB_REF':'refs/heads/master','GITHUB_SHA':MASTER,'GITHUB_EVENT_PATH':'/fixture/event.json'}
        event={'repository':{'full_name':P.REPO},'ref':'refs/heads/master','before':SHA,'after':MASTER}
        plan={'approved':True,'administration_sha':'event','operation':'release'}
        reads=lambda path,*a,**kw:json.dumps(event if str(path)=='/fixture/event.json' else plan)
        with patch.dict(A.os.environ,env,clear=True),patch.object(Path,'read_text',reads),patch.object(A.subprocess,'check_output',return_value=MASTER+'\n'),patch.object(A.subprocess,'run',return_value=Mock(returncode=1)) as changed,patch.object(A,'GitHub') as api,patch('sys.argv',['release-admin.py']),self.assertRaisesRegex(P.Rejected,'TRUSTED_FILES_MODIFIED'):
            A.main()
        paths=changed.call_args.args[0]
        self.assertIn('scripts/maven-gap-policy.py',paths)
        self.assertIn('release/maven-license-gaps.json',paths)
        api.assert_not_called()

    def test_preflight_120_minute_boundary_and_execute_never_waits(self):
        from unittest.mock import patch, Mock
        env={'GITHUB_EVENT_NAME':'push','GITHUB_REPOSITORY':P.REPO,'GITHUB_REF':'refs/heads/master','GITHUB_SHA':MASTER,'GITHUB_EVENT_PATH':'/fixture/event.json'}
        event={'repository':{'full_name':P.REPO},'ref':'refs/heads/master','before':SHA,'after':MASTER}
        plan={'approved':True,'administration_sha':'event','operation':'release'}
        reads=lambda path,*a,**kw:json.dumps(event if str(path)=='/fixture/event.json' else plan)
        for execute in (False,True):
            admin=Mock();admin.validate.side_effect=A.Pending('not terminal')
            with self.subTest(execute=execute),patch.dict(A.os.environ,env,clear=True),patch.object(Path,'read_text',reads),patch.object(A.subprocess,'check_output',return_value=MASTER+'\n'),patch.object(A.subprocess,'run',return_value=Mock(returncode=0)),patch.object(A,'GitHub'),patch.object(A,'verify_plan_changed'),patch.object(A,'Admin',return_value=admin),patch.object(A.time,'monotonic',side_effect=[100,7299,7300]),patch.object(A.time,'sleep') as sleep,patch('sys.argv',['release-admin.py']+(['--execute'] if execute else [])),self.assertRaisesRegex(P.Rejected,'REQUIRED_WORKFLOW_NOT_TERMINAL'):
                A.main()
            if execute:sleep.assert_not_called();self.assertEqual(admin.validate.call_count,1)
            else:sleep.assert_called_once_with(30);self.assertEqual(admin.validate.call_count,2)
            admin.publish.assert_not_called()

    def test_preflight_job_budget_keeps_write_budget_unchanged(self):
        source=(Path(__file__).resolve().parents[1]/'.github/workflows/release-admin.yml').read_text(encoding='utf-8')
        preflight=source.split('  preflight:',1)[1].split('  apply-approved-plan:',1)[0]
        apply=source.split('  apply-approved-plan:',1)[1]
        self.assertIn('    timeout-minutes: 130\n',preflight)
        self.assertIn('    timeout-minutes: 25\n',apply)
        self.assertNotIn('permissions:',preflight)
        self.assertIn('permissions:\n  contents: read\n  actions: read',source)
        self.assertIn('permissions:\n      contents: write\n      actions: read',apply)

    def test_required_workflow_cannot_be_omitted(self):
        class API:
            def pages(self, endpoint, key):
                return []
        admin = A.Admin(API(), {}, MASTER)
        with self.assertRaises(A.Pending):
            admin.gates(SHA)

    def test_latest_failure_cannot_use_old_success(self):
        class API:
            def pages(self, endpoint, key):
                if key == 'workflow_runs':
                    return [{'id': 1, 'status': 'completed', 'conclusion': 'success'},
                            {'id': 2, 'status': 'completed', 'conclusion': 'failure'}]
                return []
        with self.assertRaises(P.Rejected):
            A.Admin(API(), {}, MASTER).gates(SHA)

    def test_all_platform_artifacts_and_head_required(self):
        class API:
            def call(self, endpoint):
                return {'id': 7, 'expired': False, 'name': P.ARTIFACT_PREFIX['android'] + SHA,
                        'digest': 'sha256:' + 'a' * 64,
                        'workflow_run': {'head_sha': MASTER, 'id': 8}}
            def download(self, *args):
                raise AssertionError('wrong head cannot download')
        plan = {'release_sha': SHA, 'artifacts': {'android': {'id': 7, 'sha256': 'a' * 64}}}
        with self.assertRaisesRegex(P.Rejected, 'WRONG_ARTIFACT'):
            A.Admin(API(), plan, MASTER).artifacts(Path('/unused'), {'android.yml': 8})

    def test_fake_platform_string_does_not_supply_gates(self):
        plan = {'approved': True, 'format_version': 1, 'repository': P.REPO,
                'administration_sha': MASTER, 'operation': 'release', 'release_sha': SHA,
                'tag': 'v0.1.0', 'prerelease': False, 'notes': 'notes', 'final_scope_accepted': True,
                'validated_platforms': ['linux', 'windows', 'macos', 'ios', 'android'], 'artifacts': {}}
        admin = A.Admin(None, plan, MASTER)
        admin.fresh_master = lambda: None
        admin.gates = lambda *args: {}
        admin.ancestor = lambda *args: True
        with self.assertRaisesRegex(P.Rejected, 'ALL_PLATFORM'):
            admin.validate()


    def test_missing_tag_after_upload_stops_publish(self):
        admin, api, outputs = ReleaseTests().setup_admin()
        original, reads = api.call, []
        def changed(endpoint, method='GET', data=None, **kw):
            if '/git/ref/tags/' in endpoint:
                reads.append(endpoint)
                if len(reads) > 1:
                    return None
            return original(endpoint, method, data, **kw)
        api.call = changed
        with self.assertRaisesRegex(P.Rejected, 'TAG_DISAPPEARED'):
            admin.publish(outputs)
        self.assertFalse(api.writes)

    def test_post_publish_change_requires_review_not_overwrite(self):
        admin, api, outputs = ReleaseTests().setup_admin()
        original = api.call
        def changed(endpoint, method='GET', data=None, **kw):
            value = original(endpoint, method, data, **kw)
            if endpoint.endswith('/releases/12') and method == 'GET' and value['draft'] is False:
                value['prerelease'] = False
            return value
        api.call = changed
        with self.assertRaisesRegex(P.Rejected, 'METADATA_CHANGED'):
            admin.publish(outputs)
        self.assertEqual(len(api.writes), 1)

    def test_complete_checksum_rejects_tamper(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'package.zip'
            files, _ = package()
            listed = sums(files)
            files['library-release.aar'] = b'tampered'
            files['SHA256SUMS'] = listed
            write_zip(path, files, checksum=False)
            with self.assertRaisesRegex(P.Rejected, 'COVERAGE'):
                P.verify_zip(path, 'windows-x86_64', SHA, '0.1.0')


class ReviewedRebuildTests(unittest.TestCase):
    """版本重编译不替代旧功能门禁，任何不明确证据均拒绝。"""
    def run_and_jobs(self):
        run = {'id': 10, 'run_attempt': 1, 'head_sha': SHA, 'head_branch': 'master',
               'event': 'push', 'head_repository': {'full_name': P.REPO},
               'status': 'completed', 'conclusion': 'success',
               'path': '.github/workflows/release-build.yml'}
        jobs = [{'name': name, 'head_sha': SHA, 'status': 'completed', 'conclusion': 'success',
                 'steps': [{'name': 'compile', 'conclusion': 'success'}]} for name in sorted(A.REBUILD_JOBS)]
        return run, jobs

    def admin(self):
        from unittest.mock import Mock
        run, jobs = self.run_and_jobs()
        api = Mock()
        api.call.side_effect = lambda endpoint: {
            'sha': endpoint.rsplit('/', 1)[1], 'tree': {'sha': A.REBUILD_TESTED_TREE}}
        api.pages.side_effect = lambda endpoint, key: jobs if key == 'jobs' else [run]
        plan = {'approved': True, 'format_version': 1, 'repository': P.REPO,
                'administration_sha': MASTER, 'operation': 'release', 'release_sha': SHA,
                'tag_sha': MASTER, 'tag': A.REBUILD_TAG, 'prerelease': False, 'notes': 'notes',
                'final_scope_accepted': True, 'validation_mode': A.REBUILD_MODE,
                'artifacts': {name: {'id': number} for number, name in enumerate(P.PLATFORMS, 1)}}
        admin = A.Admin(api, plan, MASTER)
        admin.fresh_master = Mock()
        admin.ancestor = Mock(return_value=True)
        admin.gates = Mock(return_value={workflow: 99 for workflow in P.WORKFLOWS})
        return admin, run, jobs

    def test_only_known_mode_selects_rebuild(self):
        from unittest.mock import Mock, patch
        for mode in ('skip', '', False, 1, {}, []):
            admin, _, _ = self.admin()
            admin.plan['validation_mode'] = mode
            admin.rebuild_gates = Mock()
            with patch.object(A, 'verify_administration_scope'), self.subTest(mode=mode), \
                 self.assertRaisesRegex(P.Rejected, 'UNKNOWN_VALIDATION_MODE'):
                admin.validate()
            admin.rebuild_gates.assert_not_called()
            admin.gates.assert_not_called()
        admin, _, _ = self.admin()
        admin.rebuild_gates = Mock(return_value={'ci.yml': 10})
        with patch.object(A, 'verify_administration_scope'):
            self.assertEqual(admin.validate(), {'ci.yml': 10})
        admin.rebuild_gates.assert_called_once_with(SHA)
        admin.gates.assert_not_called()

    def test_exact_rebuild_identity_and_nonzero_required(self):
        from unittest.mock import patch
        for source, commit, tag in ((SHA, MASTER, A.REBUILD_TAG), (SHA, SHA, 'v0.1.5'),
                                    ('0' * 40, '0' * 40, A.REBUILD_TAG)):
            admin, _, _ = self.admin()
            admin.plan['tag'] = tag
            with patch.object(A, 'REBUILD_SOURCE', source), self.subTest(source=source, commit=commit, tag=tag), \
                 self.assertRaisesRegex(P.Rejected, 'REBUILD_IDENTITY_NOT_REVIEWED'):
                admin.rebuild_gates(commit)
            admin.api.call.assert_not_called()
            admin.gates.assert_not_called()

    def test_both_exact_commit_trees_are_mandatory(self):
        from unittest.mock import patch
        for target in (A.REBUILD_TESTED, A.REBUILD_RETAINED):
            for bad in ({'sha': target, 'tree': {'sha': TREE}}, {'sha': SHA, 'tree': {'sha': A.REBUILD_TESTED_TREE}},
                        {'sha': target, 'tree': {}}, {}):
                admin, _, _ = self.admin()
                def response(endpoint):
                    source = endpoint.rsplit('/', 1)[1]
                    return bad if source == target else {'sha': source, 'tree': {'sha': A.REBUILD_TESTED_TREE}}
                admin.api.call.side_effect = response
                with patch.object(A, 'REBUILD_SOURCE', SHA), patch.object(A, 'verify_exact_transition') as transition, \
                     self.subTest(target=target, bad=bad), self.assertRaisesRegex(P.Rejected, 'REBUILD_TESTED_TREE_MISMATCH'):
                    admin.rebuild_gates(SHA)
                transition.assert_not_called()
                admin.gates.assert_not_called()

    def test_all_five_artifact_roles_bind_one_exact_build_run(self):
        from unittest.mock import patch
        admin, run, _ = self.admin()
        with patch.object(A, 'REBUILD_SOURCE', SHA), patch.object(A, 'verify_exact_transition') as transition:
            result = admin.rebuild_gates(SHA)
        self.assertEqual(result, {workflow: run['id'] for workflow in P.WORKFLOWS})
        transition.assert_called_once_with(admin.api, A.REBUILD_RETAINED, SHA, A.REBUILD_SOURCE_BLOBS)
        admin.gates.assert_called_once_with(A.REBUILD_TESTED)
        self.assertEqual([call.args[0] for call in admin.api.call.call_args_list],
                         ['/repos/' + P.REPO + '/git/commits/' + source for source in (A.REBUILD_TESTED, A.REBUILD_RETAINED)])
        self.assertIn('head_sha=' + SHA + '&event=push', admin.api.pages.call_args_list[0].args[0])

    def test_original_functional_failure_and_pending_are_not_bypassed(self):
        from unittest.mock import patch
        for error in (P.Rejected('FAILED_JOB'), A.Pending('REQUIRED_WORKFLOW_PENDING')):
            admin, _, _ = self.admin()
            admin.gates.side_effect = error
            with patch.object(A, 'REBUILD_SOURCE', SHA), patch.object(A, 'verify_exact_transition'), \
                 self.subTest(error=error), self.assertRaises(type(error)):
                admin.rebuild_gates(SHA)
            admin.gates.assert_called_once_with(A.REBUILD_TESTED)
            admin.api.pages.assert_not_called()
        # Exercise the unmodified gate implementation rather than a successful mock.
        admin, _, _ = self.admin()
        admin.gates = A.Admin.gates.__get__(admin)
        admin.api.pages.side_effect = lambda endpoint, key: []
        with patch.object(A, 'REBUILD_SOURCE', SHA), patch.object(A, 'verify_exact_transition'), \
             self.assertRaisesRegex(A.Pending, 'REQUIRED_WORKFLOW_NOT_STARTED'):
            admin.rebuild_gates(SHA)
        self.assertNotIn('release-build.yml', admin.api.pages.call_args.args[0])

    def test_latest_build_failure_or_pending_cannot_choose_old_success(self):
        from unittest.mock import patch
        for changes, error in (({'id': 11, 'conclusion': 'failure'}, P.Rejected),
                               ({'id': 11, 'status': 'in_progress', 'conclusion': None}, A.Pending),
                               ({'run_attempt': 2, 'conclusion': 'failure'}, P.Rejected),
                               ({'run_attempt': 2, 'status': 'queued', 'conclusion': None}, A.Pending)):
            admin, good, jobs = self.admin()
            bad = dict(good, **changes)
            admin.api.pages.side_effect = lambda endpoint, key: jobs if key == 'jobs' else [bad, good]
            with patch.object(A, 'REBUILD_SOURCE', SHA), patch.object(A, 'verify_exact_transition'), \
                 self.subTest(changes=changes), self.assertRaises(error):
                admin.rebuild_gates(SHA)
        admin, _, _ = self.admin()
        admin.api.pages.side_effect = lambda endpoint, key: []
        with patch.object(A, 'REBUILD_SOURCE', SHA), patch.object(A, 'verify_exact_transition'), \
             self.assertRaisesRegex(A.Pending, 'REBUILD_WORKFLOW_NOT_STARTED'):
            admin.rebuild_gates(SHA)

    def test_build_run_identity_fields_are_not_interchangeable(self):
        from unittest.mock import patch
        run, jobs = self.run_and_jobs()
        for changes in ({'head_sha': MASTER}, {'head_branch': 'feat/release'}, {'event': 'workflow_dispatch'},
                        {'head_repository': {'full_name': 'other/peerloom'}}, {'head_repository': {}},
                        {'status': 'queued'}, {'conclusion': 'failure'}, {'conclusion': 'skipped'},
                        {'path': '.github/workflows/ci.yml'}):
            with patch.object(A, 'REBUILD_SOURCE', SHA), self.subTest(changes=changes), \
                 self.assertRaisesRegex(P.Rejected, 'WRONG_OR_FAILED_REBUILD'):
                A.verify_rebuild_run(dict(run, **changes), jobs, SHA)
        with patch.object(A, 'REBUILD_SOURCE', SHA), self.assertRaises(P.Rejected):
            A.verify_rebuild_run(run, jobs, MASTER)

    def test_exact_build_job_set_and_successful_steps_required(self):
        from unittest.mock import patch
        run, jobs = self.run_and_jobs()
        candidates = [jobs[:-1], jobs + [jobs[0]], jobs + [dict(jobs[0], name='extra')], []]
        missing_head = copy.deepcopy(jobs)
        del missing_head[0]['head_sha']
        candidates.append(missing_head)
        for field, value in (('head_sha', MASTER), ('status', 'queued'), ('conclusion', 'skipped'),
                             ('conclusion', 'failure'), ('steps', []), ('steps', None),
                             ('steps', [{'conclusion': 'skipped'}]), ('steps', [{'conclusion': 'failure'}]),
                             ('steps', [{'conclusion': None}])):
            changed = copy.deepcopy(jobs)
            changed[0][field] = value
            candidates.append(changed)
        for candidate in candidates:
            with patch.object(A, 'REBUILD_SOURCE', SHA), self.subTest(candidate=candidate), self.assertRaises(P.Rejected):
                A.verify_rebuild_run(run, candidate, SHA)


class ExactRebuildTransitionTests(unittest.TestCase):
    def fixture(self):
        from unittest.mock import Mock
        inventory = {'src/device-sdk/Cargo.toml': {'before_blob': SHA, 'after_blob': MASTER},
                     '.github/workflows/release-build.yml': {'before_blob': None, 'after_blob': TREE}}
        value = PushComparisonTests().comparison()
        value['files'] = [{'filename': name, 'sha': entry['after_blob'],
                           'status': 'added' if entry['before_blob'] is None else 'modified'}
                          for name, entry in inventory.items()]
        api = Mock()
        api.call.side_effect = [value, {'type': 'file', 'sha': SHA}, None]
        return api, value, inventory

    def test_exact_before_after_inventory(self):
        api, _, inventory = self.fixture()
        A.verify_exact_transition(api, SHA, MASTER, inventory)
        self.assertEqual(api.call.call_args_list[0].args[0],
                         '/repos/' + P.REPO + '/compare/' + SHA + '...' + MASTER + '?per_page=100&page=1')
        for call in api.call.call_args_list[1:]:
            self.assertTrue(call.args[0].endswith('?ref=' + SHA))
            self.assertEqual(call.kwargs, {'missing': True})

    def test_missing_extra_duplicate_and_truncated_inventory(self):
        for mutation in ('missing', 'extra', 'duplicate', 'truncated', 'empty'):
            api, value, inventory = self.fixture()
            if mutation == 'missing':
                value['files'].pop()
            elif mutation == 'extra':
                value['files'].append({'filename': 'src/product.rs', 'status': 'modified', 'sha': TREE})
            elif mutation == 'duplicate':
                value['files'].append(value['files'][0])
            elif mutation == 'truncated':
                value['files'] = [{'filename': str(i), 'status': 'added', 'sha': TREE} for i in range(300)]
            else:
                value['files'] = []
            with self.subTest(mutation=mutation), self.assertRaises(P.Rejected):
                A.verify_exact_transition(api, SHA, MASTER, inventory)

    def test_rename_delete_wrong_status_and_after_blob(self):
        for index in (0, 1):
            for change in ({'status': 'renamed'}, {'status': 'removed'}, {'previous_filename': 'src/product.rs'},
                           {'sha': '4' * 40}, {'status': 'added' if index == 0 else 'modified'}):
                api, value, inventory = self.fixture()
                value['files'][index].update(change)
                with self.subTest(index=index, change=change), self.assertRaisesRegex(P.Rejected, 'REBUILD_AFTER_BLOB_MISMATCH'):
                    A.verify_exact_transition(api, SHA, MASTER, inventory)

    def test_before_blob_and_prior_absence_required(self):
        for previous in (None, {'type': 'file', 'sha': TREE}, {'type': 'dir', 'sha': SHA}):
            api, value, inventory = self.fixture()
            api.call.side_effect = [value, previous, None]
            with self.subTest(previous=previous), self.assertRaisesRegex(P.Rejected, 'REBUILD_BEFORE_BLOB_MISMATCH'):
                A.verify_exact_transition(api, SHA, MASTER, inventory)
        api, value, inventory = self.fixture()
        api.call.side_effect = [value, {'type': 'file', 'sha': SHA}, {'type': 'file', 'sha': TREE}]
        with self.assertRaisesRegex(P.Rejected, 'REBUILD_BEFORE_BLOB_MISMATCH'):
            A.verify_exact_transition(api, SHA, MASTER, inventory)

    def test_source_must_be_retained_fast_forward_with_complete_compare(self):
        for change in ({'status': 'diverged'}, {'base_commit': {'sha': TREE}},
                       {'merge_base_commit': {'sha': TREE}}, {'behind_by': 1}, {'total_commits': 50}):
            api, value, inventory = self.fixture()
            value.update(change)
            with self.subTest(change=change), self.assertRaisesRegex(P.Rejected, 'PUSH_NOT_FAST_FORWARD'):
                A.verify_exact_transition(api, SHA, MASTER, inventory)


class RebuildAdministrationScopeTests(unittest.TestCase):
    """只允许本次已审发布管理变化，不扩展永久可写范围。"""
    def fixture(self):
        from unittest.mock import Mock
        inventory = {'scripts/test-release-admin.py': {'before_blob': SHA, 'after_blob': TREE}}
        value = PushComparisonTests().comparison()
        value['files'] = [
            {'filename': 'release/approved-plan.json', 'status': 'modified'},
            {'filename': A.EXECUTION_FILE, 'status': 'modified', 'sha': MASTER},
            {'filename': 'scripts/test-release-admin.py', 'status': 'modified', 'sha': TREE},
        ]
        api = Mock()
        api.call.side_effect = [value, {'type': 'file', 'sha': SHA}, {'type': 'file', 'sha': SHA}]
        return api, value, inventory

    def verify(self, api, inventory, source=SHA, tag=None):
        from unittest.mock import patch
        with patch.object(A, 'REBUILD_SOURCE', SHA), patch.object(A, 'REBUILD_EXECUTION_BEFORE', SHA), \
             patch.object(A, 'REBUILD_ADMIN_BLOBS', inventory):
            A.verify_administration_scope(api, source, MASTER, A.REBUILD_TAG if tag is None else tag)

    def test_only_exact_reviewed_administration_transition(self):
        api, _, inventory = self.fixture()
        self.verify(api, inventory)
        self.assertEqual([call.args[0] for call in api.call.call_args_list], [
            '/repos/' + P.REPO + '/compare/' + SHA + '...' + MASTER + '?per_page=100&page=1',
            '/repos/' + P.REPO + '/contents/' + A.EXECUTION_FILE + '?ref=' + SHA,
            '/repos/' + P.REPO + '/contents/scripts/test-release-admin.py?ref=' + SHA,
        ])
        # Scope checking is read-only; no POST/PATCH hidden behind the exception.
        self.assertTrue(all(len(call.args) == 1 and not call.kwargs for call in api.call.call_args_list))

    def test_wrong_source_or_tag_never_enables_new_allowance(self):
        for source, tag in ((TREE, A.REBUILD_TAG), (SHA, 'v0.1.3'), (SHA, 'v0.1.5'), (SHA, '')):
            api, value, inventory = self.fixture()
            value['base_commit'] = value['merge_base_commit'] = {'sha': source}
            with self.subTest(source=source, tag=tag), self.assertRaisesRegex(P.Rejected, 'ADMINISTRATION_SCOPE_NOT_REVIEWED'):
                self.verify(api, inventory, source=source, tag=tag)
            self.assertEqual(api.call.call_count, 1)

    def test_execution_must_be_present_modified_without_rename(self):
        for change in ('missing', 'added', 'removed', 'renamed', 'previous_filename'):
            api, value, inventory = self.fixture()
            if change == 'missing':
                value['files'].pop(1)
            elif change == 'previous_filename':
                value['files'][1]['previous_filename'] = 'scripts/other.py'
            else:
                value['files'][1]['status'] = change
            with self.subTest(change=change), self.assertRaisesRegex(P.Rejected, 'REVIEWED_EXECUTION_FILE_REQUIRED'):
                self.verify(api, inventory)
            self.assertEqual(api.call.call_count, 1)

    def test_execution_before_must_match_retained_source_blob(self):
        for previous in ({'type': 'file', 'sha': TREE}, {'type': 'dir', 'sha': SHA}, {}):
            api, value, inventory = self.fixture()
            api.call.side_effect = [value, previous]
            with self.subTest(previous=previous), self.assertRaisesRegex(P.Rejected, 'REBUILD_EXECUTION_BEFORE_MISMATCH'):
                self.verify(api, inventory)
            self.assertEqual(api.call.call_count, 2)

    def test_extra_product_workflow_and_execution_helpers_rejected(self):
        for name in ('src/device-sdk/Cargo.toml', 'src/device-sdk/Cargo.lock', 'src/product.rs',
                     '.github/workflows/release-build.yml', '.github/workflows/release-admin.yml',
                     'scripts/release-policy.py', 'scripts/build-release-only.py', 'docs/other.md'):
            api, value, inventory = self.fixture()
            value['files'].append({'filename': name, 'status': 'modified', 'sha': TREE})
            with self.subTest(name=name), self.assertRaisesRegex(P.Rejected, 'ADMINISTRATION_SCOPE_NOT_REVIEWED'):
                self.verify(api, inventory)

    def test_reviewed_test_inventory_and_after_blob_are_exact(self):
        for change in ('missing', 'added', 'removed', 'renamed', 'previous_filename', 'after_blob'):
            api, value, inventory = self.fixture()
            if change == 'missing':
                value['files'].pop(2)
            elif change == 'previous_filename':
                value['files'][2]['previous_filename'] = 'scripts/other.py'
            elif change == 'after_blob':
                value['files'][2]['sha'] = MASTER
            else:
                value['files'][2]['status'] = change
            with self.subTest(change=change), self.assertRaises(P.Rejected):
                self.verify(api, inventory)
        api, value, inventory = self.fixture()
        value['files'][0]['status'] = 'removed'
        with self.assertRaisesRegex(P.Rejected, 'ADMINISTRATION_RENAME_OR_DELETE'):
            self.verify(api, inventory)

    def test_reviewed_test_before_blob_cannot_drift(self):
        for previous in ({'type': 'file', 'sha': TREE}, {'type': 'dir', 'sha': SHA}, {}):
            api, value, inventory = self.fixture()
            api.call.side_effect = [value, {'type': 'file', 'sha': SHA}, previous]
            with self.subTest(previous=previous), self.assertRaisesRegex(P.Rejected, 'REBUILD_ADMIN_BEFORE_MISMATCH'):
                self.verify(api, inventory)

    def test_exception_does_not_change_permanent_or_historical_policy(self):
        self.assertEqual(P.ADMINISTRATION_FILES,
                         frozenset(('README.md', 'docs/assets/peerloom-banner.svg', 'release/approved-plan.json')))
        self.assertEqual(A.BOOTSTRAP_SOURCE, '25b33273ac5bbd03506905a635b1453dcf969c70')
        self.assertEqual(A.BOOTSTRAP_TAG, 'v0.1.3')
        self.assertEqual(set(A.REBUILD_ADMIN_BLOBS), {'scripts/test-release-admin.py'})
        for name in (A.EXECUTION_FILE, 'scripts/test-release-admin.py'):
            with self.subTest(name=name), self.assertRaisesRegex(P.Rejected, 'ADMINISTRATION_SCOPE_NOT_REVIEWED'):
                P.verify_administration_files([{'filename': name, 'status': 'modified'}])


class V015ReviewedRebuildTests(unittest.TestCase):
    """独立版本源码必须精确锁定；批准计划与全部门禁不可省略。"""
    def enabled(self):
        from unittest.mock import patch
        return patch.multiple(A, V015_SOURCE=SHA,
                              V015_ADMIN_BLOBS={'scripts/test-release-admin.py':
                                               {'before_blob': SHA, 'after_blob': TREE}})

    def admin(self):
        admin, run, jobs = ReviewedRebuildTests().admin()
        admin.plan['tag'] = A.V015_TAG
        admin.api.call.side_effect = lambda endpoint: {
            'sha': A.V015_TESTED, 'tree': {'sha': A.V015_TESTED_TREE}}
        return admin, run, jobs

    def test_unfilled_actual_source_is_disabled_without_api_calls(self):
        from unittest.mock import patch
        admin, _, _ = self.admin()
        with patch.object(A, 'V015_SOURCE', None), self.assertRaisesRegex(P.Rejected, 'REBUILD_IDENTITY_NOT_REVIEWED'):
            admin.rebuild_gates(SHA)
        admin.api.call.assert_not_called()
        admin.gates.assert_not_called()

    def test_exact_identity_rejects_zero_unknown_tag_and_missing_inventory(self):
        from unittest.mock import patch
        with self.enabled():
            for source, commit, tag, inventory in (
                ('0' * 40, '0' * 40, A.V015_TAG, A.V015_ADMIN_BLOBS),
                (SHA, MASTER, A.V015_TAG, A.V015_ADMIN_BLOBS),
                (SHA, SHA, 'v0.1.6', A.V015_ADMIN_BLOBS),
                (SHA, SHA, A.V015_TAG, {}),
            ):
                with self.subTest(source=source, tag=tag), patch.object(A, 'V015_SOURCE', source), \
                     patch.object(A, 'V015_ADMIN_BLOBS', inventory), self.assertRaises(P.Rejected):
                    A.require_v015_identity(commit, tag)

    def test_exact_tree_transition_functional_and_compile_gates_all_required(self):
        from unittest.mock import patch
        admin, _, _ = self.admin()
        with self.enabled(), patch.object(A, 'verify_exact_transition') as transition:
            self.assertEqual(admin.rebuild_gates(SHA), {workflow: 10 for workflow in P.WORKFLOWS})
        transition.assert_called_once_with(admin.api, A.V015_TESTED, SHA, A.V015_SOURCE_BLOBS)
        admin.gates.assert_called_once_with(A.V015_TESTED)

    def test_wrong_tested_tree_cannot_reuse_functional_result(self):
        from unittest.mock import patch
        admin, _, _ = self.admin()
        admin.api.call.side_effect = lambda endpoint: {'sha': A.V015_TESTED, 'tree': {'sha': TREE}}
        with self.enabled(), patch.object(A, 'verify_exact_transition') as transition, \
             self.assertRaisesRegex(P.Rejected, 'V015_TESTED_TREE_MISMATCH'):
            admin.rebuild_gates(SHA)
        transition.assert_not_called()
        admin.gates.assert_not_called()

    def test_latest_failed_compile_cannot_select_older_green(self):
        from unittest.mock import patch
        admin, run, jobs = self.admin()
        admin.api.pages.side_effect = lambda endpoint, key: jobs if key == 'jobs' else [
            run, dict(run, id=11, conclusion='failure')]
        with self.enabled(), patch.object(A, 'verify_exact_transition'), \
             self.assertRaisesRegex(P.Rejected, 'WRONG_OR_FAILED_REBUILD'):
            admin.rebuild_gates(SHA)

    def test_each_compile_job_and_step_must_succeed(self):
        _, run, jobs = self.admin()
        cases = [jobs[:-1], jobs + [jobs[0]]]
        bad = copy.deepcopy(jobs)
        bad[0]['steps'][0]['conclusion'] = 'skipped'
        cases.append(bad)
        with self.enabled():
            for candidate in cases:
                with self.subTest(candidate=candidate), self.assertRaises(P.Rejected):
                    A.verify_v015_rebuild_run(run, candidate, SHA)
            for changes in ({'head_sha': MASTER}, {'head_branch': 'fix/example'}, {'event': 'workflow_dispatch'}):
                with self.subTest(changes=changes), self.assertRaises(P.Rejected):
                    A.verify_v015_rebuild_run(dict(run, **changes), jobs, SHA)

    def test_exact_admin_inventory_and_before_blob_remain_mandatory(self):
        from unittest.mock import patch
        for tamper in (False, True):
            api, value, inventory = RebuildAdministrationScopeTests().fixture()
            if tamper:
                value['files'][-1]['sha'] = MASTER
            with self.enabled(), patch.object(A, 'V015_EXECUTION_BEFORE', SHA), \
                 patch.object(A, 'V015_ADMIN_BLOBS', inventory):
                if tamper:
                    with self.assertRaises(P.Rejected):
                        A.verify_administration_scope(api, SHA, MASTER, A.V015_TAG)
                else:
                    A.verify_administration_scope(api, SHA, MASTER, A.V015_TAG)

    def test_v015_actual_source_and_retained_identity_are_pinned(self):
        from unittest.mock import patch
        self.assertEqual(A.V015_SOURCE, '214b36b32af38f784fb08aa6746e3667a7641bbe')
        self.assertEqual(A.V015_TAG, 'v0.1.5')
        self.assertEqual(A.V015_RETAINED, A.V015_TESTED)
        admin, _, _ = self.admin()
        with self.enabled(), patch.object(A, 'V015_RETAINED', MASTER), \
             self.assertRaisesRegex(P.Rejected, 'V015_RETAINED_IDENTITY_NOT_REVIEWED'):
            admin.rebuild_gates(SHA)
        admin.api.call.assert_not_called()
        admin.gates.assert_not_called()

    def test_v014_historical_identity_and_v015_four_file_scope_are_unchanged(self):
        self.assertEqual(A.REBUILD_TAG, 'v0.1.4')
        self.assertEqual(A.REBUILD_SOURCE, '80ef5fba078822c7b6ba2e2c94b396908a1ef55e')
        self.assertEqual(A.REBUILD_TESTED, 'd2d806834821701f9ffbaad4c21cad5cc1fa18e7')
        self.assertEqual(set(A.V015_SOURCE_BLOBS), {
            'src/device-sdk/Cargo.toml', 'src/device-sdk/Cargo.lock',
            'release/build-request.json', 'release/approved-plan.json'})
        self.assertEqual(A.V015_TESTED, '5076a2224fbb43cde66eec3287b5af1a95c92b6c')


class V016ReviewedRebuildTests(unittest.TestCase):
    """本版真实构建身份与管理父链必须完整匹配；全部 API 均为离线 mock。"""
    def fixture(self):
        from unittest.mock import Mock
        import urllib.parse
        plan = {'format_version': 1, 'repository': P.REPO, 'approved': True,
                'administration_sha': MASTER, 'operation': 'release', 'release_sha': A.V016_SOURCE,
                'tag_sha': MASTER, 'tag': A.V016_TAG, 'prerelease': False, 'notes': 'fixture',
                'final_scope_accepted': True, 'validation_mode': A.REBUILD_MODE,
                'artifacts': {name: {'id': i} for i, name in enumerate(P.PLATFORMS, 1)}}
        commits = {
            A.V016_TESTED: {'sha': A.V016_TESTED, 'tree': {'sha': A.V016_TESTED_TREE}},
            A.V016_SOURCE: {'sha': A.V016_SOURCE, 'tree': {'sha': A.V016_SOURCE_TREE},
                            'parents': [{'sha': A.V016_TESTED}]},
            A.V016_ADMIN_PARENT: {'sha': A.V016_ADMIN_PARENT, 'tree': {'sha': A.V016_ADMIN_PARENT_TREE},
                                  'parents': [{'sha': A.V016_SOURCE}]},
            MASTER: {'sha': MASTER, 'parents': [{'sha': A.V016_ADMIN_PARENT}]},
        }
        source_files = [{'filename': name, 'status': 'modified', 'sha': item['after_blob']}
                        for name, item in A.V016_SOURCE_BLOBS.items()]
        admin_files = [{'filename': A.EXECUTION_FILE, 'status': 'modified', 'sha': TREE},
                       {'filename': 'release/approved-plan.json', 'status': 'modified', 'sha': A.V016_PLAN_BLOB}]
        admin_files += [{'filename': name, 'status': 'modified', 'sha': item['after_blob']}
                        for name, item in A.V016_ADMIN_BLOBS.items()]
        def comparison(before, files):
            return {'base_commit': {'sha': before}, 'merge_base_commit': {'sha': before},
                    'status': 'ahead', 'behind_by': 0, 'ahead_by': 1, 'total_commits': 1, 'files': files}
        comparisons = {(A.V016_TESTED, A.V016_SOURCE): comparison(A.V016_TESTED, source_files),
                       (A.V016_SOURCE, MASTER): comparison(A.V016_SOURCE, admin_files),
                       (A.V016_ADMIN_PARENT, MASTER): comparison(A.V016_ADMIN_PARENT, admin_files)}
        before = {name: value['before_blob'] for name, value in A.V016_SOURCE_BLOBS.items()}
        before.update({name: value['before_blob'] for name, value in A.V016_ADMIN_BLOBS.items()})
        before[A.EXECUTION_FILE] = A.V016_EXECUTION_BEFORE
        runs, jobs = {}, {}
        for i, (workflow, names) in enumerate(P.WORKFLOWS.items(), 100):
            runs[workflow] = [{'id': i, 'head_sha': A.V016_TESTED, 'head_branch': 'codex/verify-peerloom-correctness-20261031',
                              'event': 'push', 'head_repository': {'full_name': P.REPO}, 'run_attempt': 1,
                              'status': 'completed', 'conclusion': 'success', 'path': '.github/workflows/' + workflow}]
            jobs[i] = [{'name': name, 'head_sha': A.V016_TESTED, 'status': 'completed', 'conclusion': 'success',
                        'steps': [{'name': 'required', 'conclusion': 'success'}]} for name in names]
        runs['release-build.yml'] = [{'id': A.V016_BUILD_RUN, 'head_sha': A.V016_SOURCE, 'head_branch': 'master',
                                     'event': 'push', 'head_repository': {'full_name': P.REPO}, 'run_attempt': 1,
                                     'status': 'completed', 'conclusion': 'success', 'path': '.github/workflows/release-build.yml'}]
        jobs[A.V016_BUILD_RUN] = [{'name': name, 'head_sha': A.V016_SOURCE, 'status': 'completed', 'conclusion': 'success',
                                  'steps': [{'name': 'compile', 'conclusion': 'success'}]} for name in A.REBUILD_JOBS]
        state = {'commits': commits, 'comparisons': comparisons, 'before': before, 'runs': runs, 'jobs': jobs,
                 'source_files': source_files, 'admin_files': admin_files, 'master': MASTER}
        def call(endpoint, **kwargs):
            if kwargs.get('method', 'GET') != 'GET':
                raise AssertionError('offline fixture forbids writes')
            path = endpoint.removeprefix('/repos/' + P.REPO)
            if path == '/git/ref/heads/master':
                return {'object': {'sha': state['master']}}
            if path.startswith('/git/commits/'):
                return commits[path.rsplit('/', 1)[1]]
            if path.startswith('/compare/'):
                pair = tuple(path.split('/compare/', 1)[1].split('?', 1)[0].split('...'))
                return comparisons[pair]
            if path.startswith('/contents/'):
                name = urllib.parse.unquote(path.split('/contents/', 1)[1].split('?', 1)[0])
                return {'type': 'file', 'sha': before[name]}
            raise AssertionError('unexpected offline endpoint ' + path)
        def pages(endpoint, key):
            if key == 'workflow_runs':
                return runs[endpoint.split('/actions/workflows/', 1)[1].split('/runs', 1)[0]]
            return jobs[int(endpoint.split('/actions/runs/', 1)[1].split('/', 1)[0])]
        api = Mock(); api.call.side_effect = call; api.pages.side_effect = pages
        return A.Admin(api, plan, MASTER), state

    def test_exact_pinned_identity_and_eight_source_paths(self):
        self.assertEqual(A.V016_SOURCE, '150b29b428bf5c98bb0bc3864b9bfa00e74231f4')
        self.assertEqual(A.V016_SOURCE_TREE, 'a0f51d6dda2a6583a4440be7419c1482fa7be012')
        self.assertEqual(A.V016_TESTED, 'e4943daf70ee2267abe19f39c6d915c267997967')
        self.assertEqual(A.V016_RETAINED, A.V016_TESTED)
        self.assertEqual(A.V016_ADMIN_PARENT, '6dd6d244c86ab5b63bb5adc8f8e3b32abce72628')
        self.assertNotEqual(A.V016_ADMIN_PARENT, A.V016_SOURCE)
        self.assertEqual(A.V016_BUILD_RUN, 41176651461)
        self.assertEqual(set(A.V016_SOURCE_BLOBS), {
            'src/device-sdk/Cargo.toml', 'src/device-sdk/Cargo.lock', 'release/build-request.json',
            'release/approved-plan.json', 'deploy/server/README.md', 'docs/部署指南.md',
            'docs/用户使用说明.md', 'docs/发布与分支清理模块.md'})
        self.assertEqual(set(P.ADMINISTRATION_FILES), {'README.md', 'docs/assets/peerloom-banner.svg', 'release/approved-plan.json'})

    def test_full_validate_exercises_original_functional_and_exact_compile_gates(self):
        admin, _ = self.fixture()
        self.assertEqual(admin.validate(), {workflow: A.V016_BUILD_RUN for workflow in P.WORKFLOWS})
        queried = [call.args[0] for call in admin.api.pages.call_args_list]
        for workflow in P.WORKFLOWS:
            self.assertTrue(any(workflow + '/runs?head_sha=' + A.V016_TESTED in url for url in queried))
        self.assertTrue(any('release-build.yml/runs?head_sha=' + A.V016_SOURCE in url for url in queried))

    def test_zero_other_tag_or_management_sha_cannot_be_build_source(self):
        from unittest.mock import patch
        for source, commit, tag in ((None, A.V016_SOURCE, A.V016_TAG), ('0' * 40, '0' * 40, A.V016_TAG),
                                    (A.V016_SOURCE, A.V016_ADMIN_PARENT, A.V016_TAG),
                                    (A.V016_SOURCE, A.V016_SOURCE, 'v0.1.7')):
            with self.subTest(source=source, commit=commit, tag=tag), patch.object(A, 'V016_SOURCE', source), self.assertRaises(P.Rejected):
                A.require_v016_identity(commit, tag)
        admin, _ = self.fixture()
        with patch.object(A, 'V016_ADMIN_BLOBS', {}), self.assertRaises(P.Rejected):
            admin.rebuild_gates(A.V016_SOURCE)
        admin.api.call.assert_not_called()

    def test_exact_tested_tree_source_tree_and_unique_parent(self):
        for target, field, value in ((A.V016_TESTED, 'tree', {'sha': TREE}),
                                     (A.V016_SOURCE, 'tree', {'sha': TREE}),
                                     (A.V016_SOURCE, 'parents', []),
                                     (A.V016_SOURCE, 'parents', [{'sha': A.V016_ADMIN_PARENT}]),
                                     (A.V016_SOURCE, 'parents', [{'sha': A.V016_TESTED}, {'sha': MASTER}])):
            admin, state = self.fixture(); state['commits'][target][field] = value
            with self.subTest(target=target, field=field, value=value), self.assertRaises(P.Rejected):
                admin.validate()
        from unittest.mock import patch
        admin, _ = self.fixture()
        with patch.object(A, 'V016_RETAINED', MASTER), self.assertRaises(P.Rejected):
            admin.rebuild_gates(A.V016_SOURCE)
        admin.api.call.assert_not_called()

    def test_each_source_before_and_after_blob_is_required(self):
        for name in A.V016_SOURCE_BLOBS:
            for field in ('before', 'after'):
                admin, state = self.fixture()
                if field == 'before':
                    state['before'][name] = MASTER
                else:
                    next(row for row in state['source_files'] if row['filename'] == name)['sha'] = MASTER
                with self.subTest(name=name, field=field), self.assertRaises(P.Rejected):
                    admin.validate()

    def test_source_missing_extra_rename_and_truncated_comparison_rejected(self):
        for kind in ('missing', 'extra', 'rename', 'truncated', 'diverged'):
            admin, state = self.fixture(); files = state['source_files']; compare = state['comparisons'][(A.V016_TESTED, A.V016_SOURCE)]
            if kind == 'missing': files.pop()
            if kind == 'extra': files.append({'filename': 'src/unreviewed.rs', 'status': 'modified', 'sha': TREE})
            if kind == 'rename': files[0]['previous_filename'] = 'old'
            if kind == 'truncated': compare['files'] = [dict(files[0], filename=str(i)) for i in range(300)]
            if kind == 'diverged': compare['status'] = 'diverged'
            with self.subTest(kind=kind), self.assertRaises(P.Rejected): admin.validate()

    def test_each_functional_workflow_latest_failure_or_pending_is_not_bypassed(self):
        for workflow in P.WORKFLOWS:
            for status in ('failure', 'pending', 'absent'):
                admin, state = self.fixture(); rows = state['runs'][workflow]
                if status == 'absent': rows.clear()
                else: rows.append(dict(rows[0], id=rows[0]['id'] + 1000, status='in_progress' if status == 'pending' else 'completed', conclusion=None if status == 'pending' else 'failure'))
                if status == 'failure': state['jobs'][rows[-1]['id']] = state['jobs'][rows[0]['id']]
                with self.subTest(workflow=workflow, status=status), self.assertRaises(P.Rejected): admin.validate()

    def test_all_functional_jobs_and_steps_still_required(self):
        for workflow in P.WORKFLOWS:
            for field in ('job', 'step'):
                admin, state = self.fixture(); run = state['runs'][workflow][0]; jobs = state['jobs'][run['id']]
                if field == 'job': jobs.pop()
                else: jobs[0]['steps'][0]['conclusion'] = 'skipped'
                with self.subTest(workflow=workflow, field=field), self.assertRaises(P.Rejected): admin.validate()

    def test_latest_build_and_attempt_must_be_the_reviewed_success(self):
        for changes in ({'id': A.V016_BUILD_RUN + 1}, {'run_attempt': 2}, {'conclusion': 'failure'}, {'status': 'in_progress', 'conclusion': None}):
            admin, state = self.fixture(); rows = state['runs']['release-build.yml']
            if 'id' in changes or 'run_attempt' in changes:
                rows.append(dict(rows[0], **changes))
            else:
                rows[0].update(changes)
            state['jobs'][rows[-1]['id']] = state['jobs'][A.V016_BUILD_RUN]
            with self.subTest(changes=changes), self.assertRaises(P.Rejected): admin.validate()
        admin, state = self.fixture(); state['runs']['release-build.yml'].clear()
        with self.assertRaises(A.Pending): admin.validate()

    def test_compile_run_fields_and_every_job_or_step_rejected_if_wrong(self):
        for changes in ({'head_sha': A.V016_ADMIN_PARENT}, {'head_branch': 'feat/other'}, {'event': 'workflow_dispatch'},
                        {'head_repository': {'full_name': 'other/repo'}}, {'path': '.github/workflows/ci.yml'}):
            admin, state = self.fixture(); state['runs']['release-build.yml'][0].update(changes)
            with self.subTest(changes=changes), self.assertRaises(P.Rejected): admin.validate()
        for name in A.REBUILD_JOBS:
            for kind in ('missing', 'failed', 'skipped', 'wrong_source', 'duplicate'):
                admin, state = self.fixture(); jobs = state['jobs'][A.V016_BUILD_RUN]; job = next(j for j in jobs if j['name'] == name)
                if kind == 'missing': jobs.remove(job)
                if kind == 'failed': job['conclusion'] = 'failure'
                if kind == 'skipped': job['steps'][0]['conclusion'] = 'skipped'
                if kind == 'wrong_source': job['head_sha'] = A.V016_ADMIN_PARENT
                if kind == 'duplicate': jobs.append(copy.deepcopy(job))
                with self.subTest(name=name, kind=kind), self.assertRaises(P.Rejected): admin.validate()

    def test_management_parent_and_intermediate_tree_are_bound(self):
        for target, field, value in ((MASTER, 'parents', [{'sha': A.V016_SOURCE}]),
                                     (MASTER, 'parents', [{'sha': A.V016_ADMIN_PARENT}, {'sha': SHA}]),
                                     (A.V016_ADMIN_PARENT, 'tree', {'sha': TREE}),
                                     (A.V016_ADMIN_PARENT, 'parents', [{'sha': A.V016_TESTED}])):
            admin, state = self.fixture(); state['commits'][target][field] = value
            with self.subTest(target=target, field=field), self.assertRaisesRegex(P.Rejected, 'ADMIN_PARENT'): admin.validate()

    def test_management_inventory_plan_and_test_hashes_are_exact(self):
        for kind in ('missing', 'extra', 'generic_readme', 'rename', 'plan', 'test', 'before'):
            admin, state = self.fixture(); files = state['admin_files']
            if kind == 'missing': files.pop()
            if kind in ('extra', 'generic_readme'): files.append({'filename': 'README.md' if kind == 'generic_readme' else 'scripts/unreviewed.py', 'status': 'modified', 'sha': TREE})
            if kind == 'rename': files[0]['previous_filename'] = 'other'
            if kind == 'plan': next(f for f in files if f['filename'] == 'release/approved-plan.json')['sha'] = TREE
            if kind == 'test': next(f for f in files if f['filename'] == 'scripts/test-release-admin.py')['sha'] = TREE
            if kind == 'before': state['before'][A.EXECUTION_FILE] = TREE
            with self.subTest(kind=kind), self.assertRaises(P.Rejected): admin.validate()

    def test_master_drift_false_approval_unknown_mode_and_wrong_source_reject(self):
        for kind in ('master', 'approval', 'mode', 'source'):
            admin, state = self.fixture()
            if kind == 'master': state['master'] = SHA
            if kind == 'approval': admin.plan['approved'] = False
            if kind == 'mode': admin.plan['validation_mode'] = 'skip'
            if kind == 'source': admin.plan['release_sha'] = A.V016_ADMIN_PARENT
            with self.subTest(kind=kind), self.assertRaises(P.Rejected): admin.validate()

    def test_final_plan_and_candidate_test_bytes_match_the_reviewed_inventory(self):
        root = Path(__file__).resolve().parents[1]
        data = (root / 'release/approved-plan.json').read_bytes()
        plan = json.loads(data)
        # A disabled plan is allowed without publishing; an approved v016 must be exact.
        if plan.get('approved') is True and plan.get('tag') == A.V016_TAG:
            self.assertEqual(hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest(), A.V016_PLAN_BLOB)
            self.assertEqual(plan['release_sha'], A.V016_SOURCE)
            self.assertEqual(plan['tag_sha'], 'event')
            self.assertEqual(plan['validation_mode'], A.REBUILD_MODE)
            self.assertEqual(set(plan['artifacts']), set(P.PLATFORMS))
        data = Path(__file__).read_bytes()
        self.assertEqual(hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest(), A.V016_ADMIN_BLOBS['scripts/test-release-admin.py']['after_blob'])


if __name__ == '__main__':
    unittest.main()
