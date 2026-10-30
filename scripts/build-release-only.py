#!/usr/bin/env python3
"""只编译、链接和打包；功能验收证据由正式发布管理器独立验证。"""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
REPO = 'barry-ran/peerloom'
SERVER_COMMANDS = ('device-server', 'device-migrate', 'device-bootstrap', 'device-admin', 'device-admin-user')


def require(value, message):
    if not value:
        raise ValueError(message)


def validate_context(request, version, env, event, head):
    require(set(request) == {'format_version', 'version', 'tested_sha', 'retained_sha'}, 'BUILD_REQUEST_FIELDS')
    require(type(request['format_version']) is int and request['format_version'] == 1 and
            isinstance(version, str) and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version) and
            request['version'] == version, 'BUILD_REQUEST_VERSION')
    for key in ('tested_sha', 'retained_sha'):
        require(isinstance(request[key], str) and re.fullmatch('[0-9a-f]{40}', request[key]), 'BUILD_REQUEST_SHA')
    require(env.get('GITHUB_EVENT_NAME') == 'push' and env.get('GITHUB_REPOSITORY') == REPO and
            env.get('GITHUB_REF') == 'refs/heads/master' and event.get('repository', {}).get('full_name') == REPO and
            event.get('ref') == 'refs/heads/master' and not event.get('created') and
            not event.get('deleted') and not event.get('forced'), 'UNTRUSTED_BUILD_EVENT')
    require(isinstance(head, str) and re.fullmatch('[0-9a-f]{40}', head) and
            env.get('GITHUB_SHA') == head and event.get('after') == head and
            re.fullmatch('[0-9a-f]{40}', event.get('before', '')) and
            event['before'] not in ('0' * 40, head), 'BUILD_CHECKOUT_MISMATCH')
    require(not env.get('PEERLOOM_CARGO_FEATURES') and not env.get('CARGO_TARGET_DIR'), 'CUSTOM_BUILD_CONFIGURATION')


def run(args, cwd=ROOT, env=None, capture=False):
    return subprocess.run([str(a) for a in args], cwd=cwd, env=env, check=True,
                          text=True, capture_output=capture)


def package(target):
    run([sys.executable, 'scripts/package-release.py', '--platform', target,
         '--output', 'dist/release/' + target])


def linux():
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'LINUX_X64_REQUIRED')
    output = ROOT / 'dist/linux-amd64'
    output.mkdir(parents=True)
    env = dict(os.environ, CGO_ENABLED='0', GOOS='linux', GOARCH='amd64')
    for binary in SERVER_COMMANDS:
        run(['go', 'build', '-trimpath', '-o', output / binary, './cmd/' + binary], ROOT / 'src/device-server', env)
    run(['cargo', '+1.99.1', 'build', '--locked', '--release', '-p', 'device-ffi'], ROOT / 'src/device-sdk')
    abi = ROOT / 'dist/c-abi-linux-x86_64'
    (abi / 'include').mkdir(parents=True)
    (abi / 'lib').mkdir()
    for name in ('libdevice_ffi.so', 'libdevice_ffi.a'):
        shutil.copy2(ROOT / 'src/device-sdk/target/release' / name, abi / 'lib' / name)
    shutil.copy2(ROOT / 'src/device-sdk/device-ffi/include/device_sdk.h', abi / 'include/device_sdk.h')
    shutil.copy2(ROOT / 'LICENSE', abi / 'LICENSE')
    (abi / '产物范围.txt').write_text('Linux release C ABI；本次只重新编译与链接，不冒称重新运行功能验收。\n', encoding='utf-8')
    # Link the actual shipped libraries, but do not execute a lifecycle or service test.
    probe = ROOT / 'dist/link-check'
    probe.mkdir()
    common = ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic', '-pthread',
              '-I' + str(abi / 'include'), ROOT / 'src/device-sdk/device-ffi/tests/header.c']
    run(common + ['-L' + str(abi / 'lib'), '-ldevice_ffi', '-o', probe / 'header-shared'])
    run(common + [abi / 'lib/libdevice_ffi.a', '-ldl', '-lm', '-o', probe / 'header-static'])
    run([sys.executable, 'scripts/package-third-party.py', '--include-build-notices'])
    package('linux-x86_64')
    package('server-linux-amd64')


def windows():
    require(platform.system() == 'Windows' and platform.machine().lower() in ('amd64', 'x86_64'), 'WINDOWS_X64_REQUIRED')
    manifest = ROOT / 'src/device-sdk/Cargo.toml'
    target = 'x86_64-pc-windows-msvc'
    run(['cargo', '+1.99.1', 'build', '--manifest-path', manifest, '--locked', '--release', '-p', 'device-ffi', '--target', target])
    library = ROOT / 'src/device-sdk/target' / target / 'release'
    probe = ROOT / 'dist/link-check'
    probe.mkdir(parents=True)
    header = ROOT / 'src/device-sdk/device-ffi/tests/header.c'
    include = ROOT / 'src/device-sdk/device-ffi/include'
    run(['cl.exe', '/nologo', '/std:c11', '/W4', '/WX', '/MD', '/I' + str(include), header,
         library / 'device_ffi.dll.lib', '/link', '/OUT:header-shared.exe'], probe)
    result = run(['cargo', '+1.99.1', 'rustc', '--manifest-path', manifest, '-p', 'device-ffi',
                  '--lib', '--target', target, '--locked', '--release', '--', '--print', 'native-static-libs'], capture=True)
    lines = [line.split('native-static-libs:', 1)[1].strip()
             for line in (result.stdout + result.stderr).splitlines() if 'native-static-libs:' in line]
    require(len(lines) == 1, 'NATIVE_STATIC_LIBRARIES_REQUIRED')
    # rustc emits MSVC system-library filenames, never arbitrary compiler switches.
    libraries = lines[0].split()
    require(libraries and all(re.fullmatch(r'[A-Za-z0-9_.-]+\.lib', name) for name in libraries), 'INVALID_STATIC_LIBRARY_LIST')
    run(['cl.exe', '/nologo', '/std:c11', '/W4', '/WX', '/MD', '/I' + str(include), header,
         library / 'device_ffi.lib', *libraries, '/link', '/OUT:header-static.exe'], probe)
    run([sys.executable, 'scripts/package-third-party.py'])
    package('windows-x86_64')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--platform', choices=('linux', 'windows'))
    args = parser.parse_args()
    request = json.loads((ROOT / 'release/build-request.json').read_text(encoding='utf-8'))
    version = tomllib.loads((ROOT / 'src/device-sdk/Cargo.toml').read_text(encoding='utf-8'))['workspace']['package']['version']
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text(encoding='utf-8'))
    head = run(['git', 'rev-parse', 'HEAD'], capture=True).stdout.strip()
    validate_context(request, version, os.environ, event, head)
    if args.platform:
        require(not (ROOT / 'dist').exists() and not (ROOT / 'dist').is_symlink(), 'CLEAN_BUILD_OUTPUT_REQUIRED')
        {'linux': linux, 'windows': windows}[args.platform]()


if __name__ == '__main__':
    main()
