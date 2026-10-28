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

def package(platform='android'):
    meta = {'format_version': 1, 'platform': platform, 'commit': SHA, 'version': '0.1.0',
            'build_profile': 'release', 'cargo_features': 'default', 'release_evidence_complete': True,
            'evidence': {'cargo_go': 'collected-not-legally-reviewed'}}
    if platform == 'android':
        meta['evidence']['maven'] = 'collected-not-legally-reviewed'
    files = {'LICENSE': b'MIT', 'release-metadata.json': json.dumps(meta).encode()}
    scopes = ['cargo-go-all-lock-candidates'] + (['maven-configurations'] if platform == 'android' else [])
    for scope in scopes:
        prefix = 'third-party/' + scope + '/'
        proof = {'report.json': b'{"evidence_status":"collected-not-legally-reviewed"}', 'sbom.cdx.json': b'{}'}
        files.update({prefix + n: v for n, v in proof.items()})
        files[prefix + 'SHA256SUMS'] = sums(proof)
    if platform == 'android':
        files.update({'library-release.aar': b'AAR fixture', 'include/device_sdk.h': b'header'})
    return files, meta

def write_zip(path, files, checksum=True):
    with zipfile.ZipFile(path, 'w') as archive:
        for name, data in files.items():
            archive.writestr(name, data)
        if checksum:
            archive.writestr('SHA256SUMS', sums(files))

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
            self.assertEqual(P.verify_zip(path, 'android', SHA, '0.1.0')['size'], path.stat().st_size)

    def test_unlisted_extra(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'package.zip'
            files, _ = package()
            write_zip(path, files)
            with zipfile.ZipFile(path, 'a') as z:
                z.writestr('extra', b'x')
            with self.assertRaisesRegex(P.Rejected, 'COVERAGE'):
                P.verify_zip(path, 'android', SHA, '0.1.0')

    def test_symlink_zip(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'package.zip'
            entry = zipfile.ZipInfo('link')
            entry.create_system = 3
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            with zipfile.ZipFile(path, 'w') as z:
                z.writestr(entry, 'target')
            with self.assertRaisesRegex(P.Rejected, 'SPECIAL'):
                P.verify_zip(path, 'android', SHA, '0.1.0')

    def test_wrong_metadata(self):
        files, meta = package()
        for key, value in [('commit', MASTER), ('cargo_features', 'ci-diagnostics'), ('release_evidence_complete', False), ('platform', 'fake')]:
            changed = dict(meta, **{key: value})
            with self.subTest(key=key), self.assertRaises(P.Rejected):
                P.metadata(json.dumps(changed).encode(), 'android', SHA, '0.1.0')

    def test_missing_maven_evidence(self):
        _, meta = package()
        del meta['evidence']['maven']
        with self.assertRaises(P.Rejected):
            P.metadata(json.dumps(meta).encode(), 'android', SHA, '0.1.0')

    def test_linux_tar_modes_and_manifest(self):
        files, meta = package('linux-x86_64')
        modes = {}
        for target in ('linux-amd64', 'linux-arm64', 'darwin-arm64', 'windows-amd64'):
            for command in ('device-server', 'device-migrate', 'device-bootstrap', 'device-admin', 'device-admin-user'):
                name = f'go-crossbuilds/{target}/{command}' + ('.exe' if target.startswith('windows') else '')
                files[name] = b'binary'
                modes[name] = 0o644 if target.startswith('windows') else 0o755
        for name in ('sdk/lib/libdevice_ffi.so', 'sdk/lib/libdevice_ffi.a', 'sdk/include/device_sdk.h'):
            files[name] = b'abi'
        meta['executable_files'] = [n for n, m in modes.items() if m == 0o755]
        def archive(change=None):
            stream = io.BytesIO()
            all_files = dict(files, SHA256SUMS=sums(files))
            with tarfile.open(fileobj=stream, mode='w:gz') as out:
                for name, data in all_files.items():
                    item = tarfile.TarInfo(name)
                    item.size, item.mode = len(data), modes.get(name, 0o644)
                    if name == change:
                        item.mode = 0o644
                    out.addfile(item, io.BytesIO(data))
            stream.seek(0)
            return stream
        P.verify_linux_tar(archive(), {}, meta)
        with self.assertRaisesRegex(P.Rejected, 'MODES'):
            P.verify_linux_tar(archive(meta['executable_files'][0]), {}, meta)

    def test_tar_link(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as out:
            item = tarfile.TarInfo('link')
            item.type, item.linkname = tarfile.SYMTYPE, '/etc/passwd'
            out.addfile(item)
        stream.seek(0)
        with self.assertRaisesRegex(P.Rejected, 'SPECIAL'):
            P.verify_linux_tar(stream, {}, {})

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
        A.context(env, event, {'administration_sha': 'event'})
        for key, value in [('GITHUB_EVENT_NAME', 'pull_request_target'), ('GITHUB_REF', 'refs/heads/feat/test'), ('GITHUB_REPOSITORY', 'fork/repo')]:
            with self.subTest(key=key), self.assertRaises(P.Rejected):
                A.context(dict(env, **{key: value}), event, {'administration_sha': 'event'})
        for change in ({'created': True}, {'forced': True}, {'deleted': True}, {'before': 'bad'}, {'before': '0' * 40}):
            with self.subTest(change=change), self.assertRaises(P.Rejected):
                A.context(env, dict(event, **change), {'administration_sha': 'event'})

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

class CleanupTests(unittest.TestCase):
    def item(self):
        return {'branch': 'feat/foundation', 'sha': SHA, 'inactive': True, 'no_wip': True, 'proof': 'ancestor'}

    def test_allowed_exact_deletion_only(self):
        branch, sha = P.validate_cleanup(self.item(), MASTER, None, lambda a, b: True)
        cmd = P.deletion_command(branch, sha)
        self.assertEqual(cmd[-1], ':refs/heads/feat/foundation')
        self.assertIn('--force-with-lease=refs/heads/feat/foundation:' + SHA, cmd)
        self.assertNotIn('--force', cmd)

    def test_master_unrelated_active_rejected(self):
        for patch in ({'branch': 'master'}, {'branch': 'feat/user-work'}, {'inactive': False}, {'no_wip': False}):
            with self.subTest(patch=patch), self.assertRaises(P.Rejected):
                P.validate_cleanup(dict(self.item(), **patch), MASTER, None, lambda a, b: True)

    def test_equivalent_full_tree(self):
        item = dict(self.item(), proof='equivalent_tree', retained_equivalent_commit=MASTER, expected_tree=TREE)
        P.validate_cleanup(item, MASTER, lambda commit: {'tree': {'sha': TREE}}, lambda a, b: True)
        with self.assertRaisesRegex(P.Rejected, 'TREE'):
            P.validate_cleanup(item, MASTER, lambda commit: {'tree': {'sha': TREE if commit == MASTER else SHA}}, lambda a, b: True)
        with self.assertRaisesRegex(P.Rejected, 'NOT_RETAINED'):
            P.validate_cleanup(item, MASTER, lambda commit: {'tree': {'sha': TREE}}, lambda a, b: False)

    def test_ref_race_before_delete(self):
        class API:
            def call(self, endpoint, **kw):
                return {'object': {'sha': MASTER}}
        admin = A.Admin(API(), {'branches': [self.item()]}, MASTER)
        admin.ancestor = lambda a, b: True
        called = []
        with self.assertRaisesRegex(P.Rejected, 'BRANCH_MOVED'):
            admin.cleanup(called.append)
        self.assertEqual(called, [])

    def test_git_lease_rejection_propagates(self):
        class API:
            def call(self, endpoint, **kw):
                return {'object': {'sha': MASTER if endpoint.endswith('/master') else SHA}}
        admin = A.Admin(API(), {'branches': [self.item()]}, MASTER)
        admin.ancestor = lambda a, b: True
        calls = []
        def fail(command):
            calls.append(command)
            raise P.Rejected('EXACT_LEASE_DELETE_FAILED_NO_RETRY')
        with self.assertRaises(P.Rejected):
            admin.cleanup(fail)
        self.assertEqual(len(calls), 1)

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

    def test_plan_default_disabled(self):
        plan = json.loads((Path(__file__).resolve().parents[1] / 'release/approved-plan.json').read_text())
        self.assertIs(plan['approved'], False)

class ExtraBoundaryTests(unittest.TestCase):
    def test_workflow_permission_isolation(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / '.github/workflows/release-admin.yml').read_text()
        self.assertIn("on:\n  push:\n    branches: [master]\n    paths: ['release/approved-plan.json']\n", source)
        self.assertNotIn('pull_request', source)
        self.assertNotIn('workflow_dispatch', source)
        self.assertEqual(source.count('contents: write'), 1)
        read_job, write_job = source.split('  apply-approved-plan:', 1)
        self.assertNotIn('contents: write', read_job)
        self.assertIn('permissions:\n      contents: write\n      actions: read', write_job)
        self.assertEqual(source.count('persist-credentials: false'), 2)
        self.assertEqual(source.count('ref: ${{ github.sha }}'), 2)

    def test_plan_false_never_calls_api(self):
        from unittest.mock import patch
        with patch.object(A, 'GitHub', side_effect=AssertionError('must remain offline')):
            with patch('sys.argv', ['release-admin.py', '--execute']):
                A.main()

    def test_required_workflow_cannot_be_omitted(self):
        class API:
            def pages(self, endpoint, key):
                return []
        admin = A.Admin(API(), {}, MASTER)
        with self.assertRaises(A.Pending):
            admin.gates(SHA, True)

    def test_latest_failure_cannot_use_old_success(self):
        class API:
            def pages(self, endpoint, key):
                if key == 'workflow_runs':
                    return [{'id': 1, 'status': 'completed', 'conclusion': 'success'},
                            {'id': 2, 'status': 'completed', 'conclusion': 'failure'}]
                return []
        with self.assertRaises(P.Rejected):
            A.Admin(API(), {}, MASTER).gates(SHA, False)

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

    def test_no_cleanup_without_retained_commit(self):
        item = {'branch': 'feat/foundation', 'sha': SHA, 'inactive': True, 'no_wip': True, 'proof': 'ancestor'}
        with self.assertRaisesRegex(P.Rejected, 'NOT_RETAINED'):
            P.validate_cleanup(item, MASTER, None, lambda *args: False)

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
                P.verify_zip(path, 'android', SHA, '0.1.0')

if __name__ == '__main__':
    unittest.main()
