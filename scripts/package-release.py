#!/usr/bin/env python3
"""为已经通过原生测试的 release 库生成可审阅包；不签名、不发布。"""
import argparse
import hashlib
import gzip
import stat
import tarfile
import json
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tomllib

_gap_spec = importlib.util.spec_from_file_location('license_gap_policy', Path(__file__).with_name('license-gap-policy.py'))
GAPS = importlib.util.module_from_spec(_gap_spec)
_gap_spec.loader.exec_module(GAPS)
_maven_spec = importlib.util.spec_from_file_location('maven_gap_policy', Path(__file__).with_name('maven-gap-policy.py'))
MAVEN = importlib.util.module_from_spec(_maven_spec)
_maven_spec.loader.exec_module(MAVEN)

class PackageError(Exception):
    pass

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def tree_copy(source, destination):
    if source.is_symlink():
        raise PackageError('SYMLINK_INPUT')
    if source.is_file():
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        destination.chmod(0o755 if source.stat().st_mode & 0o111 else 0o644)
        return
    if not source.is_dir():
        raise PackageError('REQUIRED_PACKAGE_INPUT_MISSING')
    for path in sorted(source.rglob('*')):
        if path.is_symlink():
            raise PackageError('SYMLINK_INPUT')
        if path.is_file():
            tree_copy(path, destination / path.relative_to(source))
        elif not path.is_dir():
            raise PackageError('SPECIAL_PACKAGE_INPUT')

def check_evidence(directory):
    entries = (directory / 'SHA256SUMS').read_text(encoding='utf-8').splitlines()
    if not entries:
        raise PackageError('EMPTY_EVIDENCE_CHECKSUMS')
    seen = set()
    for line in entries:
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if not match:
            raise PackageError('INVALID_EVIDENCE_CHECKSUM')
        expected, name = match.groups()
        if name in seen or '\\' in name or ':' in name or any(p in ('', '.', '..') for p in name.split('/')) or name.startswith('/'):
            raise PackageError('UNSAFE_EVIDENCE_CHECKSUM_PATH')
        seen.add(name)
        path = directory / name
        cursor = directory
        for part in name.split('/'):
            cursor /= part
            if cursor.is_symlink():
                raise PackageError('SYMLINK_EVIDENCE')
        if not path.is_file() or digest(path) != expected:
            raise PackageError('EVIDENCE_CHECKSUM_MISMATCH')
    actual = set()
    folded = set()
    file_names = set()
    directory_names = set()
    for path in directory.rglob('*'):
        if path.is_symlink():
            raise PackageError('SYMLINK_EVIDENCE')
        name = path.relative_to(directory).as_posix()
        for part in name.split('/'):
            stem = part.split('.')[0].upper()
            if part.endswith((' ', '.')) or ':' in part or '\\' in part or any(ord(c) < 32 for c in part) or stem in {'CON', 'PRN', 'AUX', 'NUL', *[f'COM{i}' for i in range(1, 10)], *[f'LPT{i}' for i in range(1, 10)]}:
                raise PackageError('AMBIGUOUS_EVIDENCE_PATH')
        key = name.casefold()
        if key in folded:
            raise PackageError('CASEFOLD_EVIDENCE_COLLISION')
        folded.add(key)
        if path.is_file():
            file_names.add(key)
            if name != 'SHA256SUMS':
                actual.add(name)
        elif path.is_dir():
            directory_names.add(key)
        else:
            raise PackageError('SPECIAL_EVIDENCE_FILE')
    if file_names & directory_names:
        raise PackageError('EVIDENCE_FILE_DIRECTORY_COLLISION')
    if seen != actual:
        raise PackageError('UNLISTED_OR_MISSING_EVIDENCE_FILE')
    if not {'report.json', 'sbom.cdx.json'} <= seen:
        raise PackageError('REQUIRED_EVIDENCE_NOT_CHECKSUMMED')


def finish(root, output, platform, commit, sources, maven=None):
    if not re.fullmatch('[0-9a-f]{40}', commit):
        raise PackageError('EXACT_COMMIT_REQUIRED')
    if output.exists() or output.is_symlink():
        raise PackageError('OUTPUT_MUST_BE_NEW')
    if os.environ.get('PEERLOOM_CARGO_FEATURES'):
        raise PackageError('NONDEFAULT_FEATURES_REQUIRE_SEPARATE_REVIEW')
    version = tomllib.loads((root / 'src/device-sdk/Cargo.toml').read_text(encoding='utf-8'))['workspace']['package']['version']
    proof = root / 'dist/third-party'
    check_evidence(proof)
    report = json.loads((proof / 'report.json').read_text(encoding='utf-8'))
    if report.get('evidence_status') not in ('incomplete', 'collected-not-legally-reviewed'):
        raise PackageError('EVIDENCE_STATUS_INVALID')
    for name in ('sbom.cdx.json', 'report.json', '第三方告知.md', 'SHA256SUMS'):
        if not (proof / name).is_file():
            raise PackageError('EVIDENCE_FILE_MISSING')
    output.mkdir(parents=True)
    for source, destination in sources:
        tree_copy(source, output / destination)
    tree_copy(proof, output / 'third-party/cargo-go-all-lock-candidates')
    tree_copy(root / 'LICENSE', output / 'LICENSE')
    # Original provenance and modification notices remain third-party material.
    for vendor in sorted((root / 'third_party/rust').glob('*')):
        for path in sorted(vendor.iterdir()):
            if path.is_file():
                tree_copy(path, output / 'third-party/vendor' / vendor.name / path.name)
    delivery_status, documented_gaps = GAPS.classify(report)
    evidence = {'cargo_go': delivery_status}
    maven_gaps = []
    if maven:
        check_evidence(maven)
        maven_report = json.loads((maven / 'report.json').read_text(encoding='utf-8'))
        if maven_report.get('evidence_status') not in ('incomplete', 'collected-not-legally-reviewed'):
            raise PackageError('MAVEN_EVIDENCE_STATUS_INVALID')
        tree_copy(maven, output / 'third-party/maven-configurations')
        def read_maven_bound(name):
            if not re.fullmatch(r'(?:poms/[0-9a-f]{64}\.xml|licenses/[0-9a-f]{64}\.txt)', name):
                raise PackageError('UNSAFE_MAVEN_EVIDENCE_PATH')
            file = maven/name
            if not file.is_file() or file.stat().st_size > 16*1024**2:
                raise PackageError('MAVEN_EVIDENCE_MISSING_OR_TOO_LARGE')
            return file.read_bytes()
        try:
            MAVEN.verify_bound_files(maven_report, read_maven_bound)
        except ValueError as error:
            raise PackageError('MAVEN_EVIDENCE_BINDING_FAILED') from error
        evidence['maven'], maven_gaps = MAVEN.classify(maven_report)
    meta = {'format_version': 1, 'version': version, 'commit': commit, 'platform': platform, 'product': 'server' if platform == 'server-linux-amd64' else 'sdk',
            'build_profile': 'release', 'cargo_features': 'not-applicable' if platform == 'server-linux-amd64' else 'default',
            'cargo_lock_sha256': digest(root / 'src/device-sdk/Cargo.lock'),
            'evidence': evidence, 'release_evidence_complete': all(v == GAPS.COMPLETE for v in evidence.values()),
            'release_delivery_eligible': all(v in (GAPS.COMPLETE, GAPS.DOCUMENTED) for v in evidence.values()),
            'documented_gaps': documented_gaps,
            'maven_documented_gaps': maven_gaps,
            'legal_review': 'not-performed', 'signed_distribution': False,
            'inventory_scope': 'Cargo lock and Go MVS all-platform candidates; Maven resolved configurations where present; not exact binary linkage inventory'}
    if platform in ('linux-x86_64', 'server-linux-amd64'):
        meta['installation_payload'] = 'peerloom-server-linux-amd64.tar.gz' if platform == 'server-linux-amd64' else 'peerloom-linux-x86_64.tar.gz'
        meta['executable_files'] = sorted(p.relative_to(output).as_posix() for p in output.rglob('*') if p.is_file() and p.stat().st_mode & 0o111)
        (output / '安装说明.txt').write_text(f'GitHub Artifact 外层 ZIP 会丢失可执行位。请使用 {meta["installation_payload"]} 内的文件；解包后校验包内 SHA256SUMS。外层松散文件只供审阅，不作为可执行程序安装来源。\n', encoding='utf-8')
    (output / 'release-metadata.json').write_text(json.dumps(meta, ensure_ascii=False, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    entries = []
    for path in sorted(output.rglob('*')):
        if path.is_file():
            name = path.relative_to(output).as_posix()
            if any(c in name for c in '\r\n'):
                raise PackageError('UNSAFE_PACKAGE_FILENAME')
            entries.append(f'{digest(path)}  {name}\n')
    (output / 'SHA256SUMS').write_text(''.join(entries), encoding='utf-8')
    if platform in ('linux-x86_64', 'server-linux-amd64'):
        # Actions ZIP normalizes file permissions. Preserve executable modes in
        # a self-contained, deterministic-metadata tar payload, not chmod advice.
        payload = output / meta['installation_payload']
        members = sorted(p for p in output.rglob('*') if p.is_file())
        with payload.open('xb') as raw:
            with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as archive:
                    for path in members:
                        name = path.relative_to(output).as_posix()
                        info = tarfile.TarInfo(name)
                        info.size = path.stat().st_size
                        info.mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
                        info.uid = info.gid = info.mtime = 0
                        with path.open('rb') as stream:
                            archive.addfile(info, stream)
        # Outer manifest covers the immutable tar and every loose proof. The
        # tar carries its own pre-tar complete checksum list, avoiding recursion.
        for name in ('sdk', 'bin', 'infra', 'deploy', 'docs'):
            owned = output / name
            if owned.exists():
                shutil.rmtree(owned)
        outer = [f'{digest(p)}  {p.relative_to(output).as_posix()}\n' for p in sorted(output.rglob('*')) if p.is_file() and p != output / 'SHA256SUMS']
        (output / 'SHA256SUMS').write_text(''.join(outer), encoding='utf-8')
    if meta['release_evidence_complete']:
        message = 'collected, legal review pending'
    elif meta['release_delivery_eligible']:
        message = GAPS.DOCUMENTED + ': exact documented gaps retained; legal review pending'
    else:
        message = 'INCOMPLETE: unknown or unbound evidence gaps block final Release'
    print('Release-profile package created; evidence ' + message)

SERVER_BINARIES = ('device-server', 'device-migrate', 'device-bootstrap', 'device-admin', 'device-admin-user')

def server_sources(root):
    sources = [(root / 'dist/linux-amd64' / name, 'bin/' + name) for name in SERVER_BINARIES]
    migrations = ('000001_initial.down.sql', '000001_initial.up.sql', '000002_identity_replay.down.sql', '000002_identity_replay.up.sql', '000003_session_authorization.down.sql', '000003_session_authorization.up.sql', '000004_tenant_management.down.sql', '000004_tenant_management.up.sql', '000005_managed_relay.down.sql', '000005_managed_relay.up.sql', '000006_browser_administration.down.sql', '000006_browser_administration.up.sql', '000007_direct_registration.down.sql', '000007_direct_registration.up.sql', '000008_session_recovery.down.sql', '000008_session_recovery.up.sql', '000009_webhook_delivery.down.sql', '000009_webhook_delivery.up.sql', '000010_optional_capacity.down.sql', '000010_optional_capacity.up.sql')
    if {p.name for p in (root / 'infra/migrations').glob('*.sql')} != set(migrations):
        raise PackageError('SERVER_MIGRATION_SET_REQUIRED')
    sources += [(root / 'infra/migrations' / name, 'infra/migrations/' + name) for name in migrations]
    deployment = ('Dockerfile', 'Dockerfile.dockerignore', 'compose.yaml', 'compose.tls.yaml',
                  'gateway/nginx.conf', 'gateway/nginx-tls.conf', 'init-private.py', 'README.md')
    sources += [(root / 'deploy/server' / name, 'deploy/' + name) for name in deployment]
    sources.append((root / 'docs/部署指南.md', 'docs/部署指南.md'))
    return sources


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', choices=['windows-x86_64', 'apple', 'android', 'linux-x86_64', 'server-linux-amd64'], required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--apple-package')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    commit = os.environ.get('GITHUB_SHA') or subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    if args.platform == 'windows-x86_64':
        target = root / 'src/device-sdk/target/x86_64-pc-windows-msvc/release'
        sources = [(target / name, 'lib/' + name) for name in ['device_ffi.dll', 'device_ffi.dll.lib', 'device_ffi.lib']]
        sources.append((root / 'src/device-sdk/device-ffi/include/device_sdk.h', 'include/device_sdk.h'))
        sources += [(p, 'validation/' + p.name) for p in sorted((root / 'dist/validation').glob('windows-*.txt'))]
    elif args.platform == 'apple':
        if not args.apple_package:
            raise PackageError('APPLE_PACKAGE_REQUIRED')
        package = Path(args.apple_package)
        sources = [(package / 'Artifacts', 'SwiftPackage/Artifacts'), (package / 'Sources', 'SwiftPackage/Sources'), (package / 'Package.swift', 'SwiftPackage/Package.swift')]
        sources += [(p, 'validation/' + p.name) for p in sorted(package.parent.iterdir()) if p.is_file() and p.suffix in ('.txt', '.json')]
    elif args.platform == 'android':
        sources = [(root / 'dist/android/library-release.aar', 'library-release.aar'), (root / 'src/device-sdk/device-ffi/include/device_sdk.h', 'include/device_sdk.h')]
    elif args.platform == 'server-linux-amd64':
        sources = server_sources(root)
    else:
        sources = [(root / 'dist/c-abi-linux-x86_64', 'sdk')]
    finish(root, Path(args.output), args.platform, commit, sources,
           root / 'dist/android/maven-evidence' if args.platform == 'android' else None)

if __name__ == '__main__':
    try:
        main()
    except (PackageError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(str(error) if isinstance(error, PackageError) else 'RELEASE_PACKAGE_INPUT_ERROR', file=sys.stderr)
        sys.exit(1)
