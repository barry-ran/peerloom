#!/usr/bin/env python3
# MIT — Copyright (c) 2026 Peerloom contributors.
"""Build isolated pinned tools and run the mandatory real 500-peer CI fixture."""
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import shutil
import signal
import sys
import stat
import subprocess
import tempfile

PUBLIC_RESULTS = ('capacity-result.json', 'resource-samples.json')
CASES = {
    'core': ('device-core', 'sdk_scale', 'one_pc_five_hundred_real_native_peers'),
    'ffi': ('device-ffi', 'ffi_scale', 'one_c_pc_five_hundred_real_native_streams'),
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()



def command(args, root, timeout=1200):
    return subprocess.run(args, cwd=root, check=True, timeout=timeout,
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE).stdout


def source_manifest(root, expected):
    commit = command(['git', 'rev-parse', 'HEAD'], root).decode('ascii').strip()
    if commit != expected or len(commit) != 40:
        raise ValueError('source commit mismatch')
    if command(['git', 'status', '--porcelain', '--untracked-files=normal'], root).strip():
        raise ValueError('capacity CI requires clean committed source')
    paths = command(['git', 'ls-files', '-z'], root).decode('utf-8').split('\0')
    files = {}
    for name in filter(None, paths):
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('source must contain regular files only')
        files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return {'commit': commit, 'working_tree_sha256': files, 'claim': 'exact-clean-committed-source', 'build_profile': {name: os.environ.get(name, 'toolchain-default') for name in ('CARGO_BUILD_JOBS', 'CARGO_PROFILE_DEV_DEBUG', 'CARGO_PROFILE_TEST_DEBUG', 'CARGO_INCREMENTAL')}}


def select_executable(data, target='sdk_scale'):
    matches = []
    for line in data.decode('utf-8').splitlines():
        item = json.loads(line)
        if item.get('reason') == 'compiler-artifact' and item.get('target', {}).get('name') == target and 'test' in item['target'].get('kind', []) and item.get('executable'):
            matches.append(item['executable'])
    if len(matches) != 1:
        raise ValueError('exactly one selected capacity test executable required')
    return Path(matches[0]).resolve(strict=True)


def build_test(root, private, case):
    package, target, test_name = CASES[case]
    workspace = root / 'src/device-sdk'
    binding = {'case': case, 'target': target, 'test_name': test_name,
               'cargo_features': ['test-diagnostics'],
               'rust_cfg': ['peerloom_capacity_c_host'] if case == 'ffi' else []}
    if case == 'core':
        args = ['cargo', 'test', '--locked', '-p', package, '--features', 'test-diagnostics', '--test', target, '--no-run', '--message-format=json']
    else:
        native = private / 'c-adapter'; native.mkdir(mode=0o700)
        adapter = workspace / 'device-ffi/tests/capacity_host.c'
        header = workspace / 'device-ffi/include/device_sdk.h'
        obj, archive = native/'capacity_host.o', native/'libcapacity_host.a'
        command(['gcc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-I', str(header.parent), '-c', str(adapter), '-o', str(obj)], root)
        command(['ar', 'rcs', str(archive), str(obj)], root)
        binding.update(c_adapter_source_sha256=digest(adapter), c_header_sha256=digest(header),
                       c_object_sha256=digest(obj), c_archive_sha256=digest(archive),
                       c_compile_flags=['-std=c11', '-Wall', '-Wextra', '-Werror'])
        args = ['cargo', 'rustc', '--locked', '-p', package, '--features', 'test-diagnostics', '--test', target, '--message-format=json',
                '--', '--cfg', 'peerloom_capacity_c_host', '-L', 'native='+str(native)]
    executable = select_executable(command(args, workspace), target)
    listing = command([str(executable), '--list', '--format', 'terse'], root, timeout=30).decode('utf-8')
    names = [line.removesuffix(': test') for line in listing.splitlines() if line.endswith(': test')]
    if names != [test_name]:
        raise ValueError('capacity executable must expose exactly the expected real test')
    binding['sdk_test_sha256'] = digest(executable)
    return executable, binding


def export_results(runtime, results, samples, case):
    # Fixed basename allowlist only; private logs/fixtures never recursively copied.
    for name, destination in zip(PUBLIC_RESULTS, (results, samples)):
        path = runtime / name
        if path.exists():
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_size > 16 * 1024 * 1024:
                raise ValueError('invalid public evidence file')
            destination[case] = json.loads(path.read_text(encoding='utf-8'))


def validate_case_result(result, case, binding, manifest_sha256):
    if (result.get('case') != case or result.get('status') != 'passed'
            or result.get('requested_peers') != 500 or result.get('owned_processes_reaped') is not True
            or result.get('sdk_test_sha256') != binding['sdk_test_sha256']
            or result.get('source_manifest_sha256') != manifest_sha256):
        raise ValueError('case-specific real 500-peer acceptance/source/cleanup proof missing')
    if case == 'ffi' and result.get('c_adapter_source_sha256') != binding['c_adapter_source_sha256']:
        raise ValueError('C adapter source binding mismatch')


def write_results(output, results, samples, complete=False):
    if complete and (set(results) != set(CASES) or any(value.get('status') != 'passed' or value.get('owned_processes_reaped') is not True for value in results.values())):
        raise ValueError('both core and ffi cases are mandatory')
    if complete:
        if set(samples) != set(CASES):
            raise ValueError('both cases require resource samples')
        for case, rows in samples.items():
            if not isinstance(rows, list) or not rows or results[case].get('samples') != len(rows):
                raise ValueError('complete resource sample series required')
            for row in rows:
                if (not isinstance(row, dict)
                        or set(row) != {'elapsed_seconds', 'rss', 'fds', 'threads', 'cpu_seconds'}
                        or any(type(row[key]) is not int or row[key] < 0 for key in ('rss', 'fds', 'threads'))
                        or any(type(row[key]) not in (int, float) or not math.isfinite(row[key]) or row[key] < 0
                               for key in ('elapsed_seconds', 'cpu_seconds'))):
                    raise ValueError('invalid numeric resource sample')
    report = {'status': 'passed' if complete else 'failed', 'required_cases': list(CASES), 'cases': results}
    (output/'capacity-result.json').write_text(json.dumps(report, sort_keys=True, indent=2)+'\n', encoding='utf-8')
    (output/'resource-samples.json').write_text(json.dumps({'cases': samples}, sort_keys=True)+'\n', encoding='utf-8')


class Interrupted(Exception):
    pass


def install_interrupt_handlers():
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    def interrupted(_signal, _frame):
        # A repeated CI cancellation must not interrupt owned-child cleanup.
        for sig in previous:
            signal.signal(sig, signal.SIG_IGN)
        raise Interrupted('capacity CI interrupted')
    for sig in previous:
        signal.signal(sig, interrupted)
    return previous


def run_controller(args):
    process = subprocess.Popen(args, stdin=subprocess.DEVNULL)
    try:
        try:
            code = process.wait(timeout=1260)
        except subprocess.TimeoutExpired:
            raise RuntimeError('capacity controller exceeded bounded deadline') from None
        if code:
            raise RuntimeError('capacity controller failed: ' + str(code))
    finally:
        # Also runs on wrapper SIGTERM/SIGINT and unexpected exceptions, before
        # the caller can remove the controller's private runtime directory.
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=60)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
                raise RuntimeError('controller cleanup unconfirmed; CI teardown required') from None


def run_cases(root, private, binaries, selected, built, manifest_path, output):
    if set(built) != set(CASES):
        raise ValueError('both fixed capacity executables required')
    manifest_hash = digest(manifest_path)
    results, samples = {}, {}
    for case, (executable, binding) in built.items():
        # Separate service processes, private credentials and databases per case.
        runtime = private / ('runtime-' + case)
        try:
            run_controller(['python3', str(root / 'scripts/test-capacity.py'), '--root', str(root), '--pg-bin', str(selected['postgresql']), '--redis-bin', str(selected['redis']), '--server-bin', str(binaries), '--sdk-test', str(executable), '--output', str(runtime), '--source-manifest', str(manifest_path), '--peers', '500', '--case', case])
        finally:
            export_results(runtime, results, samples, case)
            write_results(output, results, samples)
        validate_case_result(results.get(case, {}), case, binding, manifest_hash)
    write_results(output, results, samples, complete=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    args.output.mkdir(mode=0o700)
    manifest = source_manifest(root, os.environ['GITHUB_SHA'])
    manifest_path = args.output / 'source-manifest.json'
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2)+'\n', encoding='utf-8')
    spec = importlib.util.spec_from_file_location('capacity_dependencies', root / 'bindings/ios/scripts/apple-service.py')
    dependencies = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dependencies)
    cache = dependencies.checked_directory(args.cache)
    selected, provenance = dependencies.dependencies(cache)
    (args.output / 'dependency-provenance.json').write_text(json.dumps(provenance, sort_keys=True)+'\n', encoding='utf-8')
    with tempfile.TemporaryDirectory(prefix='peerloom-capacity-ci-') as temporary:
        private = Path(temporary)
        binaries = private / 'bin'; binaries.mkdir(mode=0o700)
        command(['go', 'build', '-o', str(binaries) + '/', './cmd/device-server', './cmd/device-migrate', './cmd/device-admin', './cmd/device-bootstrap', './cmd/device-admin-user'], root / 'src/device-server')
        built = {case: build_test(root, private, case) for case in CASES}
        manifest['case_builds'] = {case: binding for case, (_, binding) in built.items()}
        manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2)+'\n', encoding='utf-8')
        run_cases(root, private, binaries, selected, built, manifest_path, args.output)


if __name__ == '__main__':
    previous = install_interrupt_handlers()
    try:
        main()
    except Interrupted:
        print('capacity CI interrupted after owned controller cleanup', file=sys.stderr)
        sys.exit(1)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
