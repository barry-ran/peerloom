#!/usr/bin/env python3
# MIT — Copyright (c) 2026 Peerloom contributors.
"""Owned macOS CI PostgreSQL/Redis/Go and Simulator Swift acceptance. No global services."""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import contextlib
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
ALLOWED_HOSTS = {'ftp.postgresql.org', 'download.redis.io'}
DOWNLOAD_USER_AGENT = 'Peerloom-CI/0.1 (+https://github.com/barry-ran/peerloom)'
STAGE = 'preflight'


class Failure(Exception):
    """Fixed diagnostic labels only, never arbitrary command output or credentials."""


def run(args, *, cwd=None, env=None, timeout=180, stdout=subprocess.PIPE, stderr=subprocess.PIPE):
    process = subprocess.Popen(args, cwd=cwd, env=env, stdout=stdout, stderr=stderr,
                               stdin=subprocess.DEVNULL, start_new_session=True)
    try:
        output, _ = process.communicate(timeout=timeout)
    except BaseException as error:
        # Only the process group created by this invocation. Simulator teardown below
        # owns any Xcode child that escaped this group; no name-based process sweep.
        if process.poll() is None:
            with contextlib.suppress(ProcessLookupError): os.killpg(process.pid, signal.SIGTERM)
            try: process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError): os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        for stream in (process.stdout, process.stderr):
            if stream is not None: stream.close()
        if isinstance(error, subprocess.TimeoutExpired):
            raise Failure(Path(args[0]).name + ': timeout') from None
        raise
    if process.returncode:
        raise Failure(Path(args[0]).name + ': exit ' + str(process.returncode))
    return output


def private(path, data):
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0)
    with os.fdopen(os.open(path, flags, 0o600), 'wb') as out:
        out.write(data if isinstance(data, bytes) else data.encode())


def checked_directory(path, parent=None):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise Failure('private owned directory required')
    if parent is not None and path.resolve().parent != Path(parent).resolve():
        raise Failure('directory must be a direct child of authorized root')
    return path.resolve()


def download(spec, path):
    parsed = urllib.parse.urlsplit(spec['url'])
    if parsed.scheme != 'https' or parsed.hostname not in ALLOWED_HOSTS:
        raise Failure('unapproved dependency origin')
    digest = hashlib.sha256()
    total = 0
    deadline = time.monotonic() + 180
    # No proxy credentials, redirects to other hosts, or unbounded archive reads.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(spec['url'], headers={'User-Agent': DOWNLOAD_USER_AGENT})
    try:
        response = opener.open(request, timeout=30)
    except urllib.error.HTTPError as error:
        raise Failure('dependency HTTP status ' + str(int(error.code))) from None
    with response, path.open('xb') as out:
        final = urllib.parse.urlsplit(response.url)
        if final.scheme != 'https' or final.hostname not in ALLOWED_HOSTS:
            raise Failure('unexpected dependency redirect')
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > 64 * 1024 * 1024 or time.monotonic() > deadline:
                raise Failure('dependency download bound')
            out.write(chunk)
            digest.update(chunk)
    if digest.hexdigest() != spec['sha256']:
        raise Failure('dependency checksum mismatch')


def unpack(archive, destination):
    total = 0
    count = 0
    destination.mkdir(mode=0o700)
    with tarfile.open(archive) as source:
        for member in source:
            path = PurePosixPath(member.name)
            count += 1
            if (path.is_absolute() or '..' in path.parts or '\\' in member.name or
                    not (member.isdir() or member.isfile()) or member.size > 32 * 1024 * 1024):
                raise Failure('unsafe dependency archive entry')
            total += member.size
            if total > 512 * 1024 * 1024 or count > 30000:
                raise Failure('dependency extraction bound')
            target = destination.joinpath(*path.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                data = source.extractfile(member)
                with target.open('xb') as out:
                    shutil.copyfileobj(data, out)
                target.chmod(0o700 if member.mode & 0o111 else 0o600)
                os.utime(target, (member.mtime, member.mtime), follow_symlinks=False)
    children = list(destination.iterdir())
    if len(children) != 1 or not children[0].is_dir():
        raise Failure('dependency archive requires one root')
    return children[0]


def version_matches(executable, name, version):
    if not executable.is_file():
        return False
    try:
        text = run([str(executable), '--version'], timeout=15).decode('ascii').strip()
    except (Failure, UnicodeError, OSError):
        return False
    pattern = r'postgres \(PostgreSQL\) ' + re.escape(version) + r'(?:\s.*)?' if name == 'postgresql' else r'Redis server v=' + re.escape(version) + r'\s.*'
    return re.fullmatch(pattern, text) is not None


def file_hashes(directory):
    root_info = directory.lstat()
    if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.getuid():
        raise Failure('cache prefix must be an owned directory')
    result = {}
    total = 0
    for path in sorted(directory.rglob('*')):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            target = os.readlink(path)
            if Path(target).is_absolute() or not path.resolve(strict=True).is_relative_to(directory.resolve()):
                raise Failure('cache link escapes prefix')
            result[path.relative_to(directory).as_posix()] = {'symlink': target}
            continue
        if stat.S_ISREG(info.st_mode):
            total += info.st_size
            if info.st_size > 64 * 1024 * 1024 or total > 512 * 1024 * 1024 or len(result) > 10000:
                raise Failure('compiled cache size bound')
            result[path.relative_to(directory).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def dependencies(cache):
    specs = json.loads(HERE.joinpath('apple-service-dependencies.json').read_text())
    selected = {}
    provenance = {}
    identity = {'platform': platform.machine(), 'image': os.environ.get('ImageVersion', 'local'),
                'manifest': hashlib.sha256(HERE.joinpath('apple-service-dependencies.json').read_bytes()).hexdigest(),
                'build': 'pg-no-icu-readline-zlib-v1;redis-malloc-no-lto-v1'}
    for name, spec in specs.items():
        binary = 'postgres' if name == 'postgresql' else 'redis-server'
        # Read-only existing runner installations first. Never start a system service.
        candidates = [Path(p) for p in (shutil.which(binary),
            '/opt/homebrew/opt/postgresql@18/bin/postgres' if name == 'postgresql' else '/opt/homebrew/opt/redis/bin/redis-server') if p]
        for candidate in candidates:
            if version_matches(candidate, name, spec['version']):
                selected[name] = candidate.parent
                provenance[name] = {'version': spec['version'], 'selection': 'preinstalled-runner'}
                break
        if name in selected:
            continue
        prefix = cache / name
        evidence = cache / (name + '.json')
        if prefix.exists() or evidence.exists():
            try:
                info = evidence.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_size > 2 * 1024 * 1024:
                    raise Failure('cache evidence file invalid')
                saved = json.loads(evidence.read_text())
                if (saved['identity'] != identity or saved['files'] != file_hashes(prefix) or
                        not version_matches(prefix / 'bin' / binary, name, spec['version'])):
                    raise Failure('compiled dependency cache mismatch')
            except (OSError, KeyError, ValueError):
                raise Failure('compiled dependency cache incomplete') from None
            selected[name] = prefix / 'bin'
            provenance[name] = {'version': spec['version'], 'selection': 'validated-build-cache'}
            continue
        with tempfile.TemporaryDirectory(prefix='build-', dir=cache) as temporary:
            temporary = Path(temporary)
            archive = temporary / 'archive'
            download(spec, archive)
            source = unpack(archive, temporary / 'source')
            if name == 'postgresql':
                run([str(source / 'configure'), '--prefix=' + str(prefix), '--without-icu',
                     '--without-readline', '--without-zlib'], cwd=source, timeout=180)
                run(['make', '-j3'], cwd=source, timeout=600)
                run(['make', 'install'], cwd=source, timeout=120)
            else:
                run(['make', '-j3', 'MALLOC=libc', 'OPTIMIZATION=-O2', 'BUILD_TLS=no',
                     'redis-server', 'redis-cli'], cwd=source, timeout=600)
                (prefix / 'bin').mkdir(parents=True, mode=0o700)
                for executable in ('redis-server', 'redis-cli'):
                    shutil.copy2(source / 'src' / executable, prefix / 'bin' / executable)
            notices = [item for item in source.iterdir() if item.is_file() and
                       item.name.lower().startswith(('license', 'copying', 'copyright', 'notice'))]
            if not notices: raise Failure('original dependency license text missing')
            notice_dir = prefix / 'original-notices'; notice_dir.mkdir(mode=0o700)
            for notice in notices: shutil.copy2(notice, notice_dir / notice.name)
            if not version_matches(prefix / 'bin' / binary, name, spec['version']):
                raise Failure('built dependency version mismatch')
            private(evidence, json.dumps({'identity': identity, 'files': file_hashes(prefix)}, sort_keys=True))
            selected[name] = prefix / 'bin'
            provenance[name] = {'version': spec['version'], 'selection': 'official-checksum-source-build'}
    return selected, provenance


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def fixture(client, admin):
    key = uuid.uuid4().hex
    devices = {}
    for role in ('source', 'target', 'third'):
        app = client.request('POST', '/v1/applications', 201, admin,
                             {'name': 'swift-' + role, 'require_target_approval': True}, key + role + '-app')
        grant = client.request('POST', '/v1/registration-grants', 201, admin,
                               {'application_id': app['id'], 'expires_in_seconds': 300}, key + role + '-grant')
        device = client.request('POST', '/v1/device-registrations', 201, body={
            'application_id': app['id'], 'platform': 'ios', 'installation_public_key': key + role,
            'registration_grant': grant['grant']}, key=key + role + '-register')
        devices[role] = {'application_id': app['id'], **device}
    for role in ('target', 'third'):
        client.request('POST', '/v1/connection-grants', 201, admin, {
            'source_device_id': devices['source']['device_id'], 'target_device_id': devices[role]['device_id'],
            'expires_at': (datetime.now(timezone.utc) + timedelta(minutes=20)).isoformat(),
            'expiry_action': 'terminate', 'max_sessions': 1}, key + role + '-connect')
    # No host-side registration for this fourth App: Swift must exercise its public
    # first-install API from an empty real Keychain scope, then reopen the identity.
    app = client.request('POST', '/v1/applications', 201, admin,
                         {'name': 'swift-first-registration', 'registration_mode': 'grant',
                          'require_target_approval': True}, key + '-first-app')
    grant = client.request('POST', '/v1/registration-grants', 201, admin,
                           {'application_id': app['id'], 'expires_in_seconds': 1200}, key + '-first-grant')
    devices['first_registration'] = {
        'application_id': app['id'], 'registration_grant': grant['grant'],
        'installation_public_key': key + '-first-installation', 'idempotency_key': key + '-first-register'}
    return devices


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


def interrupted(number, frame):
    # Repeated cancellation must not interrupt cleanup of already-owned resources.
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    raise Failure('interrupted signal ' + str(number))


def cleanup_owned(simulator, children, logs):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    failures = []
    if simulator:
        try: run(['xcrun', 'simctl', 'delete', simulator], timeout=45)
        except Exception: failures.append('owned-simulator')
    for process in reversed(children):
        try: stop(process)
        except Exception: failures.append('owned-process')
    for log in logs:
        try: log.close()
        except Exception: failures.append('private-log')
    return failures


def validate_device_id(value):
    value = value.strip()
    if not value.isascii() or len(value) != 36 or str(uuid.UUID(value)).lower() != value.lower():
        raise Failure('invalid owned simulator ID')
    return value


def main():
    global STAGE
    parser = argparse.ArgumentParser()
    parser.add_argument('--cache', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    if sys.platform != 'darwin' or os.environ.get('GITHUB_ACTIONS') != 'true' or os.getuid() == 0:
        raise Failure('unprivileged native macOS CI required')
    output = Path(args.output)
    output.mkdir(mode=0o700)
    checked_directory(output, os.environ['RUNNER_TEMP'])
    cache = Path(args.cache)
    if not cache.exists(): cache.mkdir(mode=0o700)
    checked_directory(cache)
    STAGE = 'dependencies'
    binaries, provenance = dependencies(cache)
    private(output / 'service-dependencies.json', json.dumps(provenance, sort_keys=True, indent=2))
    children, logs = [], []
    simulator = None
    env = dict(os.environ)
    for name in ('DATABASE_URL', 'DATABASE_URL_FILE', 'PGPASSWORD', 'PGSERVICE', 'PGSERVICEFILE',
                 'REPLAY_KEY_FILE', 'REDIS_PASSWORD_FILE', 'REDIS_ADDRESS', 'ADMIN_ORIGIN',
                 'ADMIN_DEVELOPMENT_LOOPBACK', 'TURN_SECRET_FILE', 'TURN_REGISTRY_FILE'):
        env.pop(name, None)
    env['CGO_ENABLED'] = '0'
    def launch(argv, filename):
        log = (private_dir / filename).open('xb'); logs.append(log)
        process = subprocess.Popen(argv, env=env, stdout=log, stderr=subprocess.STDOUT)
        children.append(process)
        return process
    # Only nonsecret phase labels/exit codes enter output. All server logs, DSNs and fixture
    # files stay in this temporary private directory, never in uploaded diagnostics.
    with tempfile.TemporaryDirectory(prefix='peerloom-apple-service-private-', dir=os.environ['RUNNER_TEMP']) as private_name:
        private_dir = Path(private_name)
        try:
            ports = set()
            while len(ports) < 3: ports.add(free_port())
            pgport, redisport, httpport = sorted(ports)
            password, redis_password = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            private(private_dir / 'pg-password', password)
            private(private_dir / 'redis-password', redis_password)
            private(private_dir / 'database-url', f'postgres://peerloom_test:{password}@127.0.0.1:{pgport}/postgres?sslmode=disable')
            private(private_dir / 'replay-key', base64.b64encode(secrets.token_bytes(32)))
            env.update(DATABASE_URL_FILE=str(private_dir / 'database-url'), REPLAY_KEY_FILE=str(private_dir / 'replay-key'),
                       REDIS_PASSWORD_FILE=str(private_dir / 'redis-password'), REDIS_ADDRESS=f'127.0.0.1:{redisport}',
                       LISTEN_ADDRESS=f'127.0.0.1:{httpport}')
            pg = binaries['postgresql']
            STAGE = 'initialize-isolated-postgresql'
            run([str(pg / 'initdb'), '-D', str(private_dir / 'pgdata'), '-U', 'peerloom_test',
                 '--auth-host=scram-sha-256', '--auth-local=reject', '--pwfile=' + str(private_dir / 'pg-password'),
                 '--no-locale', '--encoding=UTF8'], env=env)
            postgres = launch([str(pg / 'postgres'), '-D', str(private_dir / 'pgdata'), '-h', '127.0.0.1',
                               '-p', str(pgport), '-k', ''], 'postgres.log')
            private(private_dir / 'redis.conf', f'bind 127.0.0.1\nport {redisport}\nprotected-mode yes\nrequirepass {redis_password}\nsave ""\nappendonly no\ndir {private_dir}\n')
            redis = launch([str(binaries['redis'] / 'redis-server'), str(private_dir / 'redis.conf')], 'redis.log')
            STAGE = 'owned-dependency-readiness'
            deadline = time.monotonic() + 30
            while True:
                if postgres.poll() is not None or redis.poll() is not None: raise Failure('owned dependency exited')
                try:
                    run([str(pg / 'pg_isready'), '-h', '127.0.0.1', '-p', str(pgport)], timeout=3)
                    with socket.create_connection(('127.0.0.1', redisport), timeout=2) as sock:
                        secret = redis_password.encode()
                        sock.sendall(b'*2\r\n$4\r\nAUTH\r\n$' + str(len(secret)).encode() + b'\r\n' + secret + b'\r\n')
                        if sock.recv(64) != b'+OK\r\n': raise Failure('Redis authentication probe failed')
                    break
                except (OSError, Failure):
                    if time.monotonic() >= deadline: raise Failure('owned dependency readiness deadline')
                    time.sleep(0.1)
            STAGE = 'build-real-go'
            for executable in ('device-server', 'device-migrate', 'device-admin'):
                run(['go', 'build', '-o', str(private_dir / executable), './cmd/' + executable],
                    cwd=ROOT / 'src/device-server', env=env, timeout=300)
            STAGE = 'migrate-and-authorize'
            if postgres.poll() is not None or redis.poll() is not None: raise Failure('owned dependency exited')
            run([str(private_dir / 'device-migrate'), '--dir', str(ROOT / 'infra/migrations'), 'up'], env=env)
            admin_raw = run([str(private_dir / 'device-admin'), 'bootstrap', '--offline', '--tenant-name',
                             'swift-service-ci', '--scope', 'admin'], env=env)
            admin = json.loads(admin_raw)['service_credential']
            server = launch([str(private_dir / 'device-server')], 'server.log')
            origin = f'http://127.0.0.1:{httpport}/'
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            deadline = time.monotonic() + 30
            while True:
                if server.poll() is not None: raise Failure('Go server exited before ready')
                try:
                    with opener.open(origin + 'readyz', timeout=2) as response:
                        if response.status == 200: break
                except OSError: pass
                if time.monotonic() > deadline: raise Failure('Go readiness timeout')
                time.sleep(0.1)
            spec = importlib.util.spec_from_file_location('management', ROOT / 'scripts/test-management.py')
            management = importlib.util.module_from_spec(spec); spec.loader.exec_module(management)
            data = {'origin': origin, **fixture(management.Client(origin), admin)}
            fixture_bytes = json.dumps(data).encode()
            if len(fixture_bytes) > 65536: raise Failure('fixture size bound')
            STAGE = 'simulator-build'
            simulator = validate_device_id(run(['xcrun', 'simctl', 'create', 'PeerloomService-' + uuid.uuid4().hex,
                'com.apple.CoreSimulator.SimDeviceType.iPhone-16', 'com.apple.CoreSimulator.SimRuntime.iOS-18-5']).decode())
            private(output / 'owned-simulator.txt', simulator)
            run(['xcrun', 'simctl', 'boot', simulator], timeout=30)
            run(['xcrun', 'simctl', 'bootstatus', simulator, '-b'], timeout=180)
            package = Path(os.environ['PEERLOOM_APPLE_OUTPUT']) / 'SwiftPackage'
            if not (package / 'Artifacts/CPeerloom.xcframework').is_dir(): raise Failure('validated real XCFramework required')
            # Copy only public sources/project. Secret fixture never enters build products.
            work = private_dir / 'project'; work.mkdir()
            shutil.copytree(HERE.parent / 'SimulatorHost', work / 'SimulatorHost')
            shutil.copytree(HERE.parent / 'ServiceTests', work / 'ServiceTests')
            (work / 'SwiftPackage').symlink_to(package, target_is_directory=True)
            project = work / 'SimulatorHost/PeerloomSimulatorHost.xcodeproj'
            derived = private_dir / 'DerivedData'
            command = ['xcodebuild', '-project', str(project), '-scheme', 'PeerloomSwiftService',
                       '-destination', 'platform=iOS Simulator,id=' + simulator, '-derivedDataPath', str(derived),
                       'CODE_SIGNING_ALLOWED=YES', 'CODE_SIGN_IDENTITY=-', 'DEVELOPMENT_TEAM=']
            with (output / 'service-build.log').open('xb') as build_log:
                # Build before provisioning fixture; this subprocess gets no DB/Redis config.
                run(command + ['build-for-testing'], env=dict(os.environ), timeout=600,
                    stdout=build_log, stderr=subprocess.STDOUT)
            app = derived / 'Build/Products/Debug-iphonesimulator/PeerloomSimulatorHost.app'
            run(['xcrun', 'simctl', 'install', simulator, str(app)], timeout=60)
            container = Path(run(['xcrun', 'simctl', 'get_app_container', simulator,
                                  'io.peerloom.validation.simulatorhost', 'data'], timeout=30).decode().strip()).resolve()
            device_root = Path.home() / 'Library/Developer/CoreSimulator/Devices' / simulator / 'data'
            if not container.is_relative_to(device_root.resolve(strict=True)) or not container.is_dir():
                raise Failure('Simulator returned unexpected owned container')
            documents = container / 'Documents'; documents.mkdir(exist_ok=True)
            private(documents / 'peerloom-service-fixture.json', fixture_bytes)
            STAGE = 'real-swift-service-xctest'
            # xcresult stays PRIVATE: test process environment/crash attachment could include
            # synthetic secrets. Only parsed counts + fixed test name are published.
            result = private_dir / 'service.xcresult'
            test_status = 0
            try:
                with (private_dir / 'runtime.log').open('xb') as runtime_log:
                    run(command + ['-resultBundlePath', str(result), 'test-without-building'], env=dict(os.environ),
                        stdout=runtime_log, stderr=subprocess.STDOUT, timeout=300)
            except Failure:
                test_status = 1
            allowed = ('fixture loaded', 'Swift first registration persisted in Keychain',
                       'Swift reopen restored the same registered device',
                       'Keychain identities loaded and three SDKs online',
                       'two explicitly approved sessions ready', 'three typed channels ready',
                       'real Go/WSS + DP Keychain + 3 devices/2 connections + message/low/256KiB stream/duplex/FIN + parent-child gate passed')
            progress = (private_dir / 'runtime.log').read_text(errors='replace')
            labels = ['[Swift service] ' + label for label in allowed if '[Swift service] ' + label in progress]
            labels += ['[Swift service] native_error_code=' + code for code in re.findall(r'\[Swift service\] native_error_code=([0-9]{1,3})(?:\s|$)', progress)]
            private(output / 'service-progress.log', '\n'.join(labels) + '\n')
            # Post-test metadata cannot prevent actual execution. Both checks must pass.
            signing = importlib.util.spec_from_file_location('signing', HERE / 'inspect-test-signing.py')
            inspector = importlib.util.module_from_spec(signing); signing.loader.exec_module(inspector)
            with (private_dir / 'signing.log').open('w') as signing_log, contextlib.redirect_stdout(signing_log):
                inspector.inspect(derived / 'Build/Products', Path(os.environ['DEVELOPER_DIR']),
                                  require_host=True, test_bundle='PeerloomServiceTests.xctest')
            if test_status: raise Failure('xcodebuild service test failed')
            summary = json.loads(run(['xcrun', 'xcresulttool', 'get', 'test-results', 'summary', '--path', str(result)], timeout=30))
            if summary['totalTestCount'] != 1 or summary['failedTests'] != 0:
                raise Failure('real service XCTest must execute exactly one passing scenario')
            if not re.search(r"Test Case [^\n]*\bSwiftServiceTests\b[^\n]*\btestRealGoKeychainThreeDevicesAndThreeChannelModes\b[^\n]*\bpassed\b", progress):
                raise Failure('named real service XCTest passed evidence missing')
            private(output / 'service-evidence.json', json.dumps({'status': 'passed', 'test_count': 1,
                'test': 'SwiftServiceTests.testRealGoKeychainThreeDevicesAndThreeChannelModes',
                'native_sdk': True, 'swift_first_registration': True, 'swift_reopen_same_identity': True,
                'go_postgresql_redis': True, 'actual_app_host_verified': True, 'storage': 'Simulator DP Keychain',
                'transport': 'loopback-development HTTP/WSS and real WebRTC', 'physical_device': False,
                'production_signing': False, 'original_native_tests_replaced': False}, indent=2))
        finally:
            cleanup_failures = cleanup_owned(simulator, children, logs)
            if cleanup_failures:
                private(output / 'cleanup-failure.txt', '\n'.join(cleanup_failures) + '\n')
    if cleanup_failures: raise Failure('owned resource cleanup failed')
    print('Apple real service acceptance passed; synthetic secrets and xcresult withheld')


if __name__ == '__main__':
    os.umask(0o077)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        main()
    except Exception as error:
        label = str(error) if isinstance(error, Failure) else type(error).__name__
        print('Apple service phase ' + STAGE + ': ' + label + '; command output and secrets withheld', file=sys.stderr)
        raise SystemExit(1)
