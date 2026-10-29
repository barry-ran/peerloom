#!/usr/bin/env python3
# MIT — Copyright (c) 2026 Peerloom contributors.
"""Build isolated pinned tools and run the mandatory real 500-peer CI fixture."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import stat
import subprocess
import tempfile

PUBLIC_RESULTS = ('capacity-result.json', 'resource-samples.json')


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


def select_executable(data):
    matches = []
    for line in data.decode('utf-8').splitlines():
        item = json.loads(line)
        if item.get('reason') == 'compiler-artifact' and item.get('target', {}).get('name') == 'sdk_scale' and 'test' in item['target'].get('kind', []) and item.get('executable'):
            matches.append(item['executable'])
    if len(matches) != 1:
        raise ValueError('exactly one sdk_scale test executable required')
    return Path(matches[0]).resolve(strict=True)


def export_results(runtime, output):
    # Never recursively copy the fixture directory: it may contain private logs.
    for name in PUBLIC_RESULTS:
        path = runtime / name
        if path.exists():
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_size > 16 * 1024 * 1024:
                raise ValueError('invalid public evidence file')
            json.loads(path.read_text(encoding='utf-8'))
            shutil.copyfile(path, output / name)


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
        executable = select_executable(command(['cargo', 'test', '--locked', '-p', 'device-core', '--test', 'sdk_scale', '--no-run', '--message-format=json'], root / 'src/device-sdk'))
        runtime = private / 'runtime'
        try:
            run_controller(['python3', str(root / 'scripts/test-capacity.py'), '--root', str(root), '--pg-bin', str(selected['postgresql']), '--redis-bin', str(selected['redis']), '--server-bin', str(binaries), '--sdk-test', str(executable), '--output', str(runtime), '--source-manifest', str(manifest_path), '--peers', '500'])
        finally:
            export_results(runtime, args.output)
        result = json.loads((args.output / 'capacity-result.json').read_text(encoding='utf-8'))
        if result.get('status') != 'passed' or result.get('requested_peers') != 500 or not result.get('owned_processes_reaped'):
            raise ValueError('real 500-peer acceptance/cleanup proof missing')


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
