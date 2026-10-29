#!/usr/bin/env python3
"""发布证据纯校验；不访问网络、不解包、不执行产物。"""
import hashlib
import json
import importlib.util
import plistlib
from pathlib import Path
import re
import stat
import tarfile
import zipfile

_gap_spec = importlib.util.spec_from_file_location('license_gap_policy', Path(__file__).with_name('license-gap-policy.py'))
GAPS = importlib.util.module_from_spec(_gap_spec)
_gap_spec.loader.exec_module(GAPS)
_maven_spec = importlib.util.spec_from_file_location('maven_gap_policy', Path(__file__).with_name('maven-gap-policy.py'))
MAVEN = importlib.util.module_from_spec(_maven_spec)
_maven_spec.loader.exec_module(MAVEN)

REPO = 'barry-ran/peerloom'
WORKFLOWS = {
    'ci.yml': {'verify', 'capacity-500'},
    'native.yml': {'windows-native', 'apple-native'},
    'android.yml': {'android-build', 'android-emulator-4096', 'android-emulator-16384'},
    'admin-web.yml': {'PostgreSQL + Chromium 管理安全门禁'},
}
PLATFORMS = {'linux-x86_64': 'ci.yml', 'windows-x86_64': 'native.yml',
             'apple': 'native.yml', 'android': 'android.yml', 'server-linux-amd64': 'ci.yml'}
ARTIFACT_PREFIX = {'linux-x86_64': 'peerloom-linux-release-', 'windows-x86_64': 'peerloom-windows-release-',
                   'apple': 'peerloom-apple-release-', 'android': 'peerloom-android-release-',
                   'server-linux-amd64': 'peerloom-server-linux-amd64-release-'}
SERVER_COMMANDS = frozenset(('device-server', 'device-migrate', 'device-bootstrap', 'device-admin', 'device-admin-user'))
SERVER_DEPLOY = frozenset('deploy/' + name for name in (
    'Dockerfile', 'Dockerfile.dockerignore', 'compose.yaml', 'compose.tls.yaml',
    'gateway/nginx.conf', 'gateway/nginx-tls.conf', 'init-private.py'))
SERVER_SQL = frozenset('infra/migrations/' + name + '.' + direction + '.sql'
                      for name in ('000001_initial', '000002_identity_replay', '000003_session_authorization',
                                   '000004_tenant_management', '000005_managed_relay', '000006_browser_administration',
                                   '000007_direct_registration', '000008_session_recovery', '000009_webhook_delivery', '000010_optional_capacity', '000011_exclusive_sessions')
                      for direction in ('up', 'down'))
SERVER_DOCS = frozenset(('docs/部署指南.md', 'deploy/README.md'))
SERVER_BINARIES = frozenset('bin/' + name for name in SERVER_COMMANDS)
LINUX_SDK_FILES = frozenset(('sdk/lib/libdevice_ffi.so', 'sdk/lib/libdevice_ffi.a', 'sdk/include/device_sdk.h', 'sdk/LICENSE', 'sdk/产物范围.txt'))
INSTALL_PAYLOADS = {'linux-x86_64': 'peerloom-linux-x86_64.tar.gz',
                    'server-linux-amd64': 'peerloom-server-linux-amd64.tar.gz'}
MAX_FILES = 20000
MAX_EXPANDED = 4 * 1024**3
MAX_ARCHIVE = 1024**3
MAX_JSON = 16 * 1024**2
RESERVED = {'CON', 'PRN', 'AUX', 'NUL', *[f'COM{i}' for i in range(1, 10)], *[f'LPT{i}' for i in range(1, 10)]}

class Rejected(ValueError):
    pass

def require(value, message):
    if not value:
        raise Rejected(message)

# Exact documentation/plan paths, never scripts/**, workflows/** or arbitrary Markdown.
ADMINISTRATION_FILES = frozenset((
    'README.md', 'docs/assets/peerloom-banner.svg', 'release/approved-plan.json',
))


def verify_administration_files(files, bootstrap=None):
    require(isinstance(files, list) and 0 < len(files) < 300, 'COMPARE_FILE_LIST_UNPROVEN')
    names = set()
    for item in files:
        require(isinstance(item, dict), 'COMPARE_FILE_LIST_INVALID')
        name = item.get('filename')
        require(isinstance(name, str) and name not in names, 'COMPARE_FILE_LIST_INVALID')
        names.add(name)
        require(item.get('status') in ('added', 'modified') and
                'previous_filename' not in item, 'ADMINISTRATION_RENAME_OR_DELETE')
        if name in ADMINISTRATION_FILES:
            continue
        require(bootstrap is not None, 'ADMINISTRATION_SCOPE_NOT_REVIEWED')
        require(name in bootstrap['files'], 'ADMINISTRATION_SCOPE_NOT_REVIEWED')
        entry = bootstrap['files'][name]
        require(item.get('sha') == entry['after_blob'] and
                item['status'] == ('added' if entry['before_blob'] is None else 'modified'),
                'BOOTSTRAP_FILE_BLOB_MISMATCH')
    if bootstrap is not None:
        require(set(bootstrap['files']) == names - ADMINISTRATION_FILES,
                'BOOTSTRAP_INVENTORY_MISMATCH')


def release_asset_name(platform, tag):
    require(platform in PLATFORMS and isinstance(tag, str) and
            re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?', tag), 'INVALID_ASSET_IDENTITY')
    if platform == 'server-linux-amd64':
        return f'peerloom-server-{tag}-linux-amd64.zip'
    return f'peerloom-sdk-{tag}-{platform}.zip'

def sha(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{40}', value), 'EXACT_SHA_REQUIRED')
    return value

def path_name(name, directory=False):
    require(isinstance(name, str) and 0 < len(name) <= 1024, 'UNSAFE_PATH')
    if directory and name.endswith('/'):
        name = name[:-1]
    parts = name.split('/')
    require(all(p and p not in ('.', '..') and not p.endswith((' ', '.'))
                and p.split('.')[0].upper() not in RESERVED for p in parts), 'UNSAFE_PATH')
    require(not any(c in name for c in '\\:') and all(ord(c) >= 32 and ord(c) != 127 for c in name), 'UNSAFE_PATH')
    return name

class Names:
    def __init__(self):
        self.entries = {}
    def add(self, name, directory=False):
        name = path_name(name, directory)
        key = name.casefold()
        require(key not in self.entries, 'DUPLICATE_CASEFOLD_PATH')
        for existing, is_dir in self.entries.items():
            require(not (key.startswith(existing + '/') and not is_dir), 'FILE_DIRECTORY_COLLISION')
            require(not (existing.startswith(key + '/') and not directory), 'FILE_DIRECTORY_COLLISION')
        self.entries[key] = directory
        return name

def checksum_manifest(data, actual):
    require(len(data) <= 4 * 1024**2, 'CHECKSUM_LIST_TOO_LARGE')
    expected = {}
    for line in data.decode('utf-8').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        require(match is not None, 'INVALID_CHECKSUM_LINE')
        digest, name = match.groups()
        name = path_name(name)
        require(name not in expected and name != 'SHA256SUMS', 'DUPLICATE_CHECKSUM')
        expected[name] = digest
    require(expected == actual, 'FULL_CHECKSUM_COVERAGE_MISMATCH')

def hash_stream(stream):
    return hashlib.file_digest(stream, 'sha256').hexdigest()

def metadata(data, platform, commit, version):
    require(len(data) <= MAX_JSON, 'METADATA_TOO_LARGE')
    value = json.loads(data)
    require(value.get('format_version') == 1 and value.get('platform') == platform and
            value.get('commit') == commit and value.get('version') == version and
            value.get('build_profile') == 'release' and
            value.get('cargo_features') == ('not-applicable' if platform == 'server-linux-amd64' else 'default') and
            value.get('product') == ('server' if platform == 'server-linux-amd64' else 'sdk'), 'PACKAGE_IDENTITY_MISMATCH')
    keys = {'cargo_go', 'maven'} if platform == 'android' else {'cargo_go'}
    evidence = value.get('evidence')
    require(isinstance(evidence, dict) and set(evidence) == keys and
            evidence['cargo_go'] in (GAPS.COMPLETE, GAPS.DOCUMENTED) and
            (platform != 'android' or evidence['maven'] in (GAPS.COMPLETE, GAPS.DOCUMENTED)), 'INCOMPLETE_EVIDENCE')
    complete = all(status == GAPS.COMPLETE for status in evidence.values())
    require(value.get('release_evidence_complete') is complete, 'MISREPRESENTED_EVIDENCE_COMPLETENESS')
    if not complete:
        require(value.get('release_delivery_eligible') is True and isinstance(value.get('documented_gaps'), list)
                and isinstance(value.get('maven_documented_gaps', []), list)
                and (value['documented_gaps'] or value.get('maven_documented_gaps')), 'DOCUMENTED_GAPS_REQUIRED')
    return value

def verify_linux_tar(stream, outer_hashes, meta):
    names = Names()
    hashes, modes = {}, {}
    checksum = None
    total = 0
    with tarfile.open(fileobj=stream, mode='r|gz') as archive:
        for count, item in enumerate(archive, 1):
            require(count <= MAX_FILES and item.size >= 0, 'TAR_LIMIT')
            require(item.isfile() or item.isdir(), 'TAR_SPECIAL_MEMBER')
            name = names.add(item.name, item.isdir())
            require(item.uid == item.gid == 0 and item.mode in (0o644, 0o755), 'TAR_MODE_OR_OWNER')
            if item.isdir():
                require(item.mode == 0o755, 'TAR_DIRECTORY_MODE')
                continue
            total += item.size
            require(total <= MAX_EXPANDED, 'TAR_LIMIT')
            modes[name] = item.mode
            with archive.extractfile(item) as member:
                if name == 'SHA256SUMS':
                    require(item.size <= 4 * 1024**2, 'CHECKSUM_LIST_TOO_LARGE')
                    checksum = member.read()
                else:
                    hashes[name] = hash_stream(member)
    require(checksum is not None, 'TAR_CHECKSUM_REQUIRED')
    checksum_manifest(checksum, hashes)
    executable = meta.get('executable_files')
    require(isinstance(executable, list) and len(executable) == len(set(executable)), 'EXECUTABLE_LIST_REQUIRED')
    require(set(executable) == {n for n, m in modes.items() if m == 0o755}, 'EXECUTABLE_MODES_MISMATCH')
    platform = meta.get('platform')
    require(platform in INSTALL_PAYLOADS, 'TAR_PLATFORM_REQUIRED')
    if platform == 'server-linux-amd64':
        required = SERVER_BINARIES | SERVER_DEPLOY | SERVER_SQL | SERVER_DOCS
        require(required <= hashes.keys(), 'SERVER_DEPLOYMENT_FILE_MISSING')
        require(set(executable) == SERVER_BINARIES | {'deploy/init-private.py'}, 'SERVER_EXECUTABLE_MODES')
    else:
        required = LINUX_SDK_FILES
        require(required <= hashes.keys(), 'LINUX_ABI_MISSING')
    common = {'LICENSE', 'release-metadata.json', '安装说明.txt'}
    require(common <= hashes.keys(), 'INSTALL_PROOF_MISSING')
    for name in hashes:
        require(name in required | common or
                name.startswith(('third-party/cargo-go-all-lock-candidates/', 'third-party/vendor/')),
                'UNEXPECTED_INSTALL_FILE')
    # No binary/config payload is allowed only inside the tar without a known role;
    # all variable third-party proof files must also be independently verified outside it.
    proof_names = {name for name in hashes if name.startswith('third-party/')}
    require(proof_names == {name for name in outer_hashes if name.startswith('third-party/')}, 'TAR_PROOF_SET_MISMATCH')
    for name, digest in outer_hashes.items():
        if name != INSTALL_PAYLOADS[platform]:
            require(hashes.get(name) == digest, 'LOOSE_PROOF_DIFFERS_FROM_TAR')
    require(set(outer_hashes) == common | proof_names | {INSTALL_PAYLOADS[platform]}, 'UNEXPECTED_OUTER_INSTALL_FILE')
    return hashes

def verify_zip(filename, platform, commit, version):
    sha(commit)
    require(platform in PLATFORMS and filename.stat().st_size <= MAX_ARCHIVE, 'ARCHIVE_LIMIT')
    names, hashes, entries = Names(), {}, {}
    total = 0
    with zipfile.ZipFile(filename) as archive:
        for count, item in enumerate(archive.infolist(), 1):
            require(count <= MAX_FILES and not item.flag_bits & 1, 'ZIP_LIMIT_OR_ENCRYPTION')
            name = names.add(item.filename, item.is_dir())
            mode = item.external_attr >> 16
            require(stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR), 'ZIP_SPECIAL_MEMBER')
            require(not (item.is_dir() and stat.S_IFMT(mode) == stat.S_IFREG), 'ZIP_TYPE_MISMATCH')
            if item.is_dir():
                continue
            require(stat.S_IFMT(mode) != stat.S_IFDIR, 'ZIP_TYPE_MISMATCH')
            total += item.file_size
            require(total <= MAX_EXPANDED, 'ZIP_LIMIT')
            entries[name] = item
            if name != 'SHA256SUMS':
                with archive.open(item) as stream:
                    hashes[name] = hash_stream(stream)
        require({'SHA256SUMS', 'release-metadata.json', 'LICENSE'} <= entries.keys(), 'PACKAGE_ROOT_MISSING')
        require(entries['SHA256SUMS'].file_size <= 4 * 1024**2, 'CHECKSUM_LIST_TOO_LARGE')
        checksum_manifest(archive.read(entries['SHA256SUMS']), hashes)
        require(entries['release-metadata.json'].file_size <= MAX_JSON, 'METADATA_TOO_LARGE')
        meta = metadata(archive.read(entries['release-metadata.json']), platform, commit, version)
        proofs = ['third-party/cargo-go-all-lock-candidates']
        if platform == 'android':
            proofs.append('third-party/maven-configurations')
        for prefix in proofs:
            require({prefix + '/report.json', prefix + '/sbom.cdx.json', prefix + '/SHA256SUMS'} <= entries.keys(), 'PROOF_MISSING')
            require(entries[prefix + '/SHA256SUMS'].file_size <= 4 * 1024**2, 'CHECKSUM_LIST_TOO_LARGE')
            nested = {name[len(prefix)+1:]: value for name, value in hashes.items() if name.startswith(prefix + '/') and name != prefix + '/SHA256SUMS'}
            checksum_manifest(archive.read(entries[prefix + '/SHA256SUMS']), nested)
            require(entries[prefix + '/report.json'].file_size <= MAX_JSON, 'REPORT_TOO_LARGE')
            report = json.loads(archive.read(entries[prefix + '/report.json']))
            if prefix.endswith('cargo-go-all-lock-candidates'):
                status, gaps = GAPS.classify(report)
                for package in report.get('packages', []):
                    for notice in package.get('files', []):
                        notice_path = prefix + '/' + path_name(notice['file'])
                        require(hashes.get(notice_path) == notice.get('sha256'), 'LICENSE_NOTICE_MISSING_OR_CHANGED')
                require(status in (GAPS.COMPLETE, GAPS.DOCUMENTED) and
                        meta['evidence']['cargo_go'] == status and meta.get('documented_gaps', []) == gaps,
                        'UNBOUND_OR_UNKNOWN_LICENSE_GAPS')
            else:
                status, gaps = MAVEN.classify(report)
                def read_maven_bound(name):
                    name = prefix + '/' + path_name(name)
                    require(name in entries and entries[name].file_size <= MAX_JSON, 'MAVEN_EVIDENCE_MISSING_OR_TOO_LARGE')
                    return archive.read(entries[name])
                try:
                    MAVEN.verify_bound_files(report, read_maven_bound)
                except ValueError as error:
                    raise Rejected('MAVEN_EVIDENCE_BINDING_FAILED') from error
                require(status in (GAPS.COMPLETE, GAPS.DOCUMENTED) and meta['evidence']['maven'] == status
                        and meta.get('maven_documented_gaps', []) == gaps, 'UNBOUND_OR_UNKNOWN_MAVEN_GAPS')

        if platform != 'server-linux-amd64':
            server_names = SERVER_COMMANDS | {name + '.exe' for name in SERVER_COMMANDS}
            require(not any(n.startswith(('bin/', 'go-crossbuilds/', 'infra/', 'deploy/')) or
                            (not n.startswith('third-party/') and n.rsplit('/', 1)[-1] in server_names)
                            for n in entries), 'SDK_CONTAINS_SERVER_PAYLOAD')
        if platform in INSTALL_PAYLOADS:
            payload = INSTALL_PAYLOADS[platform]
            require(meta.get('installation_payload') == payload and payload in entries, 'LINUX_PAYLOAD_REQUIRED')
            require(not any(n.startswith(('sdk/', 'go-crossbuilds/', 'bin/', 'infra/', 'deploy/', 'docs/')) for n in entries), 'DUPLICATED_BINARY_PAYLOAD')
            with archive.open(entries[payload]) as stream:
                verify_linux_tar(stream, hashes, meta)
        else:
            required = {
                'windows-x86_64': {'lib/device_ffi.dll', 'lib/device_ffi.dll.lib', 'lib/device_ffi.lib', 'include/device_sdk.h'},
                'apple': {'SwiftPackage/Package.swift', 'SwiftPackage/Artifacts/CPeerloom.xcframework/Info.plist'},
                'android': {'library-release.aar', 'include/device_sdk.h'},
            }[platform]
            require(required <= entries.keys(), 'PLATFORM_BINARY_MISSING')
            if platform == 'apple':
                prefix = 'SwiftPackage/Artifacts/CPeerloom.xcframework/'
                require(entries[prefix + 'Info.plist'].file_size <= MAX_JSON, 'PLIST_TOO_LARGE')
                info = plistlib.loads(archive.read(entries[prefix + 'Info.plist']))
                expected = {('ios', ''): {'arm64'}, ('ios', 'simulator'): {'arm64', 'x86_64'}, ('macos', ''): {'arm64', 'x86_64'}}
                seen, header_hashes = set(), set()
                for library in info['AvailableLibraries']:
                    key = (library['SupportedPlatform'], library.get('SupportedPlatformVariant', ''))
                    require(key in expected and key not in seen and set(library['SupportedArchitectures']) == expected[key], 'APPLE_SLICES_MISMATCH')
                    seen.add(key)
                    identifier = path_name(library['LibraryIdentifier'])
                    binary = prefix + identifier + '/' + path_name(library['LibraryPath'])
                    header = prefix + identifier + '/' + path_name(library['HeadersPath']) + '/device_sdk.h'
                    require(binary in hashes and header in hashes, 'APPLE_NATIVE_SLICE_MISSING')
                    header_hashes.add(hashes[header])
                require(seen == set(expected) and len(header_hashes) == 1, 'APPLE_SLICES_OR_HEADER_MISMATCH')

    with filename.open('rb') as stream:
        digest = hash_stream(stream)
    return {'sha256': digest, 'size': filename.stat().st_size}

def verify_run(run, jobs, workflow, commit):
    require(workflow in WORKFLOWS and run.get('head_sha') == commit and run.get('event') == 'push' and
            run.get('head_repository', {}).get('full_name') == REPO and run.get('status') == 'completed' and
            run.get('conclusion') == 'success' and run.get('path') == '.github/workflows/' + workflow, 'WRONG_OR_FAILED_RUN')
    names = [j.get('name') for j in jobs]
    require(len(names) == len(set(names)) and set(names) == WORKFLOWS[workflow], 'CANONICAL_JOBS_MISSING')
    for job in jobs:
        require(job.get('head_sha', commit) == commit and job.get('conclusion') == 'success' and job.get('status') == 'completed', 'FAILED_JOB')
        require(job.get('steps') and all(s.get('conclusion') == 'success' for s in job['steps']), 'SKIPPED_OR_FAILED_STEP')
