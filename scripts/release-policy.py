#!/usr/bin/env python3
"""发布证据纯校验；不访问网络、不解包、不执行产物。"""
import hashlib
import json
import plistlib
import re
import stat
import tarfile
import zipfile

REPO = 'barry-ran/peerloom'
WORKFLOWS = {
    'ci.yml': {'verify'},
    'native.yml': {'windows-native', 'apple-native'},
    'android.yml': {'android-build', 'android-emulator-4096', 'android-emulator-16384'},
    'admin-web.yml': {'PostgreSQL + Chromium 管理安全门禁'},
}
PLATFORMS = {'linux-x86_64': 'ci.yml', 'windows-x86_64': 'native.yml',
             'apple': 'native.yml', 'android': 'android.yml'}
ARTIFACT_PREFIX = {'linux-x86_64': 'peerloom-linux-release-', 'windows-x86_64': 'peerloom-windows-release-',
                   'apple': 'peerloom-apple-release-', 'android': 'peerloom-android-release-'}
# Explicit task refs, never a prefix wildcard. Active refs still require a reviewed inactive proof.
TASK_BRANCHES = frozenset('''feat/foundation feat/identity-transport validation/identity-transport
feat/validation-identity-transport feat/validation-control-plane feat/validation-sdk-facade
feat/validation-tenant-management feat/validation-native-ffi feat/validation-linux-storage
feat/validation-managed-turn feat/validation-native-platforms feat/validation-admin-console
feat/validation-platform-fixes feat/validation-apple-diagnostics feat/validation-apple-keychain
feat/validation-android feat/validation-managed-ice feat/validation-android-stability
feat/validation-multichannel feat/validation-release-packaging'''.split())
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
            value.get('build_profile') == 'release' and value.get('cargo_features') == 'default', 'PACKAGE_IDENTITY_MISMATCH')
    keys = {'cargo_go', 'maven'} if platform == 'android' else {'cargo_go'}
    require(value.get('release_evidence_complete') is True and
            value.get('evidence') == {key: 'collected-not-legally-reviewed' for key in keys}, 'INCOMPLETE_EVIDENCE')
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
    for target in ('linux-amd64', 'linux-arm64', 'darwin-arm64', 'windows-amd64'):
        for command in ('device-server', 'device-migrate', 'device-bootstrap', 'device-admin', 'device-admin-user'):
            name = f'go-crossbuilds/{target}/{command}' + ('.exe' if target.startswith('windows') else '')
            require(name in hashes, 'GO_BINARY_MISSING')
            if not target.startswith('windows'):
                require(modes[name] == 0o755, 'GO_EXECUTABLE_MODE')
    require({'sdk/lib/libdevice_ffi.so', 'sdk/lib/libdevice_ffi.a', 'sdk/include/device_sdk.h'} <= hashes.keys(), 'LINUX_ABI_MISSING')
    for name, digest in outer_hashes.items():
        if name != 'peerloom-linux-x86_64.tar.gz':
            require(hashes.get(name) == digest, 'LOOSE_PROOF_DIFFERS_FROM_TAR')
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
            require(entries[prefix + '/report.json'].file_size <= MAX_JSON, 'REPORT_TOO_LARGE')
            report = json.loads(archive.read(entries[prefix + '/report.json']))
            require(report.get('evidence_status') == 'collected-not-legally-reviewed', 'INCOMPLETE_EVIDENCE')
        if platform == 'linux-x86_64':
            payload = 'peerloom-linux-x86_64.tar.gz'
            require(meta.get('installation_payload') == payload and payload in entries, 'LINUX_PAYLOAD_REQUIRED')
            require(not any(n.startswith(('sdk/', 'go-crossbuilds/')) for n in entries), 'DUPLICATED_BINARY_PAYLOAD')
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

def validate_cleanup(item, master, get_commit, is_ancestor):
    branch = item.get('branch')
    require(branch in TASK_BRANCHES and item.get('inactive') is True and item.get('no_wip') is True, 'BRANCH_NOT_APPROVED')
    original = sha(item.get('sha'))
    if item.get('proof') == 'ancestor':
        require(is_ancestor(original, master), 'BRANCH_NOT_RETAINED')
    elif item.get('proof') == 'equivalent_tree':
        retained = sha(item.get('retained_equivalent_commit'))
        tree = sha(item.get('expected_tree'))
        require(is_ancestor(retained, master), 'EQUIVALENT_COMMIT_NOT_RETAINED')
        require(get_commit(original)['tree']['sha'] == get_commit(retained)['tree']['sha'] == tree, 'TREE_NOT_IDENTICAL')
    else:
        raise Rejected('UNKNOWN_RETENTION_PROOF')
    return branch, original

def deletion_command(branch, expected):
    require(branch in TASK_BRANCHES, 'BRANCH_NOT_APPROVED')
    sha(expected)
    ref = 'refs/heads/' + branch
    return ['git', '-c', 'credential.helper=', 'push', '--porcelain',
            '--force-with-lease=' + ref + ':' + expected,
            'https://github.com/' + REPO + '.git', ':' + ref]
