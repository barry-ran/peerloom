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
    entries = (directory / 'SHA256SUMS').read_text().splitlines()
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
    version = tomllib.loads((root / 'src/device-sdk/Cargo.toml').read_text())['workspace']['package']['version']
    proof = root / 'dist/third-party'
    check_evidence(proof)
    report = json.loads((proof / 'report.json').read_text())
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
    if maven:
        check_evidence(maven)
        maven_report = json.loads((maven / 'report.json').read_text())
        if maven_report.get('evidence_status') not in ('incomplete', 'collected-not-legally-reviewed'):
            raise PackageError('MAVEN_EVIDENCE_STATUS_INVALID')
        tree_copy(maven, output / 'third-party/maven-configurations')
        evidence['maven'] = maven_report['evidence_status']
    meta = {'format_version': 1, 'version': version, 'commit': commit, 'platform': platform,
            'build_profile': 'release', 'cargo_features': 'default',
            'cargo_lock_sha256': digest(root / 'src/device-sdk/Cargo.lock'),
            'evidence': evidence, 'release_evidence_complete': all(v == GAPS.COMPLETE for v in evidence.values()),
            'release_delivery_eligible': all(v in (GAPS.COMPLETE, GAPS.DOCUMENTED) for v in evidence.values()),
            'documented_gaps': documented_gaps,
            'legal_review': 'not-performed', 'signed_distribution': False,
            'inventory_scope': 'Cargo lock and Go MVS all-platform candidates; Maven resolved configurations where present; not exact binary linkage inventory'}
    if platform == 'linux-x86_64':
        meta['installation_payload'] = 'peerloom-linux-x86_64.tar.gz'
        meta['executable_files'] = sorted(p.relative_to(output).as_posix() for p in output.rglob('*') if p.is_file() and p.stat().st_mode & 0o111)
        (output / '安装说明.txt').write_text('GitHub Artifact 外层 ZIP 会丢失可执行位。请使用 peerloom-linux-x86_64.tar.gz 内的文件；解包后校验包内 SHA256SUMS。外层松散文件只供审阅，不作为可执行程序安装来源。\n')
    (output / 'release-metadata.json').write_text(json.dumps(meta, ensure_ascii=False, indent=2, sort_keys=True) + '\n')
    entries = []
    for path in sorted(output.rglob('*')):
        if path.is_file():
            name = path.relative_to(output).as_posix()
            if any(c in name for c in '\r\n'):
                raise PackageError('UNSAFE_PACKAGE_FILENAME')
            entries.append(f'{digest(path)}  {name}\n')
    (output / 'SHA256SUMS').write_text(''.join(entries))
    if platform == 'linux-x86_64':
        # Actions ZIP normalizes file permissions. Preserve executable modes in
        # a self-contained, deterministic-metadata tar payload, not chmod advice.
        payload = output / 'peerloom-linux-x86_64.tar.gz'
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
        for name in ('sdk', 'go-crossbuilds'):
            owned = output / name
            if owned.exists():
                shutil.rmtree(owned)
        outer = [f'{digest(p)}  {p.relative_to(output).as_posix()}\n' for p in sorted(output.rglob('*')) if p.is_file() and p != output / 'SHA256SUMS']
        (output / 'SHA256SUMS').write_text(''.join(outer))
    if meta['release_evidence_complete']:
        message = 'collected, legal review pending'
    elif meta['release_delivery_eligible']:
        message = GAPS.DOCUMENTED + ': exact documented gaps retained; legal review pending'
    else:
        message = 'INCOMPLETE: unknown or unbound evidence gaps block final Release'
    print('Release-profile package created; evidence ' + message)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', choices=['windows-x86_64', 'apple', 'android', 'linux-x86_64'], required=True)
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
    else:
        sources = [(root / 'dist/c-abi-linux-x86_64', 'sdk')]
        sources += [(root / 'dist' / target, 'go-crossbuilds/' + target) for target in ['linux-amd64', 'linux-arm64', 'darwin-arm64', 'windows-amd64']]
    finish(root, Path(args.output), args.platform, commit, sources,
           root / 'dist/android/maven-evidence' if args.platform == 'android' else None)

if __name__ == '__main__':
    try:
        main()
    except (PackageError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(str(error) if isinstance(error, PackageError) else 'RELEASE_PACKAGE_INPUT_ERROR', file=sys.stderr)
        sys.exit(1)
