#!/usr/bin/env python3
"""Real Windows Go/SDK/DPAPI; only Redis runs in a task-owned WSL1 distribution."""
import argparse
import base64
import hashlib
import importlib.util
from datetime import datetime, timedelta, timezone
import uuid
import unicodedata
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import secrets
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.error
import urllib.request
import zipfile

HOSTS = {'cdimage.ubuntu.com', 'download.redis.io', 'get.enterprisedb.com'}
STAGE = 'preflight'


def validate_scope(directory, distro, env, platform):
    if platform != 'win32' or env.get('GITHUB_ACTIONS') != 'true':
        raise ValueError('native Windows CI required')
    if not re.fullmatch(r'PeerloomCI-[a-f0-9]{32}', distro):
        raise ValueError('invalid owned distribution name')
    base = Path(env['RUNNER_TEMP']).resolve()
    directory = Path(directory).resolve()
    if directory.parent != base or directory.name != distro or not directory.is_dir():
        raise ValueError('private task directory required')
    return directory


def download(spec, destination):
    parsed = urllib.parse.urlparse(spec['url'])
    if parsed.scheme != 'https' or parsed.hostname not in HOSTS:
        raise ValueError('non-official download')
    digest = hashlib.sha256()
    size = 0
    deadline = time.monotonic() + 300
    request = urllib.request.Request(spec['url'], headers={
        'User-Agent': 'Peerloom-CI/0.1 (+https://github.com/barry-ran/peerloom)'})
    with urllib.request.urlopen(request, timeout=60) as response, destination.open('xb') as out:
        final = urllib.parse.urlparse(response.url)
        if final.scheme != 'https' or final.hostname not in HOSTS:
            raise ValueError('unexpected download redirect')
        while chunk := response.read(1024 * 1024):
            if time.monotonic() >= deadline:
                raise TimeoutError('official download deadline')
            size += len(chunk)
            if size > 512 * 1024 * 1024:
                raise ValueError('archive exceeds bound')
            digest.update(chunk)
            out.write(chunk)
    if digest.hexdigest() != spec['sha256']:
        raise ValueError('official archive checksum mismatch')


def extract_postgres(archive, destination):
    with zipfile.ZipFile(archive) as data:
        total = 0
        for item in data.infolist():
            path = PurePosixPath(item.filename)
            if path.is_absolute() or '..' in path.parts or '\\' in item.filename or ':' in item.filename:
                raise ValueError('unsafe archive path')
            if (item.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError('archive symlink not accepted')
            total += item.file_size
            if total > 3 * 1024 ** 3:
                raise ValueError('archive expands beyond bound')
        data.extractall(destination)


def wsl_mounted_path(path):
    # The official fresh base uses WSL's default automount. Verify access before use;
    # never edit wsl.conf or mount/network settings to make this assumption true.
    value = str(path)
    if not re.match(r'^[A-Za-z]:[\\/]', value):
        raise ValueError('local drive path required')
    return '/mnt/' + value[0].lower() + '/' + value[3:].replace('\\', '/')


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def bounded_wsl_text(data, redactions):
    if not data:
        return ''
    # WSL on Windows emits either UTF-8 or UTF-16LE. Decode before redaction;
    # never print undecoded bytes/base64 or a second unredacted interpretation.
    if len(data) > 8192:
        return '[WSL diagnostic output exceeded safe input bound]'
    bounded = data
    encoding = 'utf-16-le' if bounded.startswith(b'\xff\xfe') or bounded.count(b'\x00') > len(bounded) // 8 else 'utf-8'
    text = bounded.decode(encoding, errors='replace').lstrip('\ufeff')
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text)
    text = ''.join(c if c in '\n\t' or not unicodedata.category(c).startswith('C') else '' for c in text)
    for value in sorted({v for v in redactions if isinstance(v, str) and len(v) > 2}, key=len, reverse=True):
        for variant in {value, value.replace('\\', '/'), value.replace('/', '\\')}:
            text = re.sub(re.escape(variant), '[owned-path]', text, flags=re.I)
    # 1 KiB per diagnostic including multibyte text, never split a UTF-8 scalar.
    return text.encode('utf-8')[-768:].decode('utf-8', errors='ignore')


def wsl_import_diagnostic(returncode, output, errors, redactions=()):
    # Do not mix UTF-16 stdout with UTF-8 stderr before decoding.
    text = bounded_wsl_text(output, redactions) + '\n' + bounded_wsl_text(errors, redactions)
    text = text.encode('utf-8')[-768:].decode('utf-8', errors='ignore')
    return 'Owned WSL1 import diagnostic: exit=' + str(int(returncode)) + ' text=' + text


def owned_wsl_redactions(argv):
    root = str(PureWindowsPath(argv[3]).parent) if re.match(r'^[A-Za-z]:', argv[3]) else str(Path(argv[3]).parent)
    return [argv[2], argv[3], argv[4], root, os.environ.get('USERPROFILE', ''),
            os.environ.get('HOME', ''), os.environ.get('RUNNER_TEMP', '')]


def wsl_status_diagnostic(redactions):
    try:
        result = subprocess.run(['wsl.exe', '--status'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=20, check=False)
        text = wsl_import_diagnostic(result.returncode, result.stdout, result.stderr, redactions)
        print(text.replace('Owned WSL1 import diagnostic:', 'Read-only WSL status diagnostic:', 1), file=sys.stderr)
    except (OSError, subprocess.TimeoutExpired) as error:
        print('Read-only WSL status diagnostic unavailable: category=' + type(error).__name__, file=sys.stderr)


def run(argv, *, env=None, cwd=None, timeout=180, stdout=subprocess.PIPE, import_diagnostic=False):
    process = subprocess.Popen(argv, env=env, cwd=cwd, stdout=stdout, stderr=subprocess.PIPE)
    try:
        output, errors = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        # Keep the admitted parent alive until Windows can identify its descendant
        # tree. subprocess.run would kill cargo first and orphan the Rust test.
        tree_stopped = False
        if sys.platform == 'win32' and process.poll() is None:
            try:
                result = subprocess.run(['taskkill.exe', '/PID', str(process.pid), '/T', '/F'],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                        timeout=20, check=False)
                tree_stopped = result.returncode == 0
            except (OSError, subprocess.TimeoutExpired):
                tree_stopped = False
        if process.poll() is None:
            process.kill()
        process.wait(timeout=10)
        if not tree_stopped:
            raise RuntimeError('owned child tree cleanup unconfirmed') from None
        raise TimeoutError('owned command deadline') from None
    if process.returncode:
        if import_diagnostic and len(argv) == 7 and argv[:2] == ['wsl.exe', '--import'] and argv[-2:] == ['--version', '1']:
            print(wsl_import_diagnostic(process.returncode, output, errors, owned_wsl_redactions(argv)), file=sys.stderr)
        # Never include command/environment or arbitrary server stderr in CI logs.
        raise RuntimeError('child command failed')
    return output


def redis_ready(port, password):
    with socket.create_connection(('127.0.0.1', port), timeout=2) as sock:
        stream = sock.makefile('rb')
        for command, expected in ((['AUTH', password], b'+OK\r\n'), (['PING'], b'+PONG\r\n'),
                                  (['EVAL', "return 'peerloom-ci'", '0'], b'$11\r\n')):
            request = ('*%d\r\n' % len(command)).encode()
            for part in command:
                raw = part.encode()
                request += ('$%d\r\n' % len(raw)).encode() + raw + b'\r\n'
            sock.sendall(request)
            if stream.readline(128) != expected:
                raise RuntimeError('Redis authentication/Lua probe failed')
        if stream.readline(128) != b'peerloom-ci\r\n':
            raise RuntimeError('Redis Lua value mismatch')


def create_authorized_pair(client, credential):
    # Reuse the bounded HTTP client, not its Unix-only 0600 file adapter.
    if not credential.startswith('svc_') or len(credential) != 47:
        raise ValueError('private service credential shape')
    prefix = uuid.uuid4().hex
    pair = {}
    for name in ('source', 'target'):
        app = client.request('POST', '/v1/applications', 201, credential,
                             {'name': 'native-windows-' + name, 'require_target_approval': True}, prefix + name + '-app')
        grant = client.request('POST', '/v1/registration-grants', 201, credential,
                               {'application_id': app['id'], 'expires_in_seconds': 300}, prefix + name + '-grant')
        device = client.request('POST', '/v1/device-registrations', 201, body={
            'application_id': app['id'], 'platform': 'windows',
            'installation_public_key': 'native-windows-' + uuid.uuid4().hex,
            'registration_grant': grant['grant']}, key=prefix + name + '-device')
        pair[name] = {'application_id': app['id'], **device}
    client.request('POST', '/v1/connection-grants', 201, credential, {
        'source_device_id': pair['source']['device_id'], 'target_device_id': pair['target']['device_id'],
        'expires_at': (datetime.now(timezone.utc) + timedelta(minutes=20)).isoformat(),
        'expiry_action': 'terminate', 'max_sessions': 1}, prefix + '-connection')
    return pair


def main():
    global STAGE
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', required=True)
    parser.add_argument('--distro', required=True)
    args = parser.parse_args()
    directory = validate_scope(args.directory, args.distro, os.environ, sys.platform)
    root = Path(__file__).resolve().parent.parent
    dependencies = json.loads((root / 'scripts/windows-service-dependencies.json').read_text())
    children, handles = [], []
    imported = False
    pg_started = False
    pg = None
    env = dict(os.environ)
    env["CGO_ENABLED"] = "0"
    for key in ('DATABASE_URL', 'DATABASE_URL_FILE', 'REPLAY_KEY_FILE', 'REDIS_PASSWORD_FILE',
                'REDIS_ADDRESS', 'ADMIN_ORIGIN', 'ADMIN_DEVELOPMENT_LOOPBACK', 'TURN_SECRET_FILE'):
        env.pop(key, None)
    def wsl(*command, timeout=180):
        return run(['wsl.exe', '--distribution', args.distro, '--exec', *command], timeout=timeout)
    def private(name, value):
        path = directory / name
        with path.open('x', encoding='utf-8') as out:
            out.write(value)
        return path
    def launch(argv, name):
        output = (directory / name).open('xb')
        handles.append(output)
        process = subprocess.Popen(argv, env=env, stdout=output, stderr=subprocess.STDOUT)
        children.append(process)
        return process
    try:
        for name, spec in dependencies.items():
            STAGE = 'download-' + name
            download(spec, directory / (name + '.archive'))
        STAGE = 'extract-postgresql'
        extract_postgres(directory / 'postgresql.archive', directory / 'postgresql')
        pg = directory / 'postgresql/pgsql/bin'
        assert b'18.6' in run([str(pg / 'postgres.exe'), '--version'])
        STAGE = 'import-owned-wsl1'
        wsl_status_diagnostic([str(directory), args.distro, os.environ.get('USERPROFILE', ''),
                               os.environ.get('HOME', ''), os.environ.get('RUNNER_TEMP', '')])
        imported = True  # An uncertain result is checked/cleaned; import is never repeated.
        run(['wsl.exe', '--import', args.distro, str(directory / 'wsl'),
             str(directory / 'ubuntu_base.archive'), '--version', '1'], timeout=180, import_diagnostic=True)
        # No default distribution/version/network setting is changed.
        STAGE = 'build-real-redis-in-owned-wsl1'
        wsl('/bin/bash', '-ec', 'mkdir -m 700 /root/peerloom-ci; apt-get update; '
            'DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential ca-certificates', timeout=600)
        archive = wsl_mounted_path(directory / 'redis.archive')
        wsl('/usr/bin/test', '-f', archive)
        wsl('/bin/tar', '-xf', archive, '-C', '/root/peerloom-ci', '--strip-components=1')
        wsl('/usr/bin/make', '-C', '/root/peerloom-ci/src', '-j2', 'MALLOC=libc',
            'redis-server', 'redis-cli', timeout=600)
        assert b'v=8.10.3' in wsl('/root/peerloom-ci/src/redis-server', '--version')
        pgport, redisport, httpport = free_port(), free_port(), free_port()
        password, redispassword = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        pg_password = private('pg-password', password)
        redis_password = private('redis-password', redispassword)
        database = private('database-url', f'postgres://peerloom_test:{password}@127.0.0.1:{pgport}/postgres?sslmode=disable')
        replay = private('replay-key', base64.b64encode(secrets.token_bytes(32)).decode())
        env.update(PGPASSWORD=password, DATABASE_URL_FILE=str(database), REPLAY_KEY_FILE=str(replay),
                   REDIS_PASSWORD_FILE=str(redis_password), REDIS_ADDRESS=f'127.0.0.1:{redisport}',
                   LISTEN_ADDRESS=f'127.0.0.1:{httpport}')
        STAGE = 'start-private-native-postgresql'
        run([str(pg / 'initdb.exe'), '-D', str(directory / 'data'), '-U', 'peerloom_test',
             '--auth-host=scram-sha-256', '--auth-local=reject', '--pwfile=' + str(pg_password),
             '--no-locale', '--encoding=UTF8'], env=env)
        pg_started = True
        run([str(pg / 'pg_ctl.exe'), '-D', str(directory / 'data'), '-l', str(directory / 'postgres.log'),
             '-o', f'-h 127.0.0.1 -p {pgport}', '-w', 'start'], env=env)
        STAGE = 'start-private-real-redis'
        config = private('redis.conf', f'bind 127.0.0.1\nport {redisport}\nprotected-mode yes\nrequirepass {redispassword}\nsave ""\nappendonly no\ndir /root/peerloom-ci\n')
        config_wsl = wsl_mounted_path(config)
        wsl('/usr/bin/test', '-f', config_wsl)
        wsl('/bin/cp', config_wsl, '/root/peerloom-ci/redis.conf')
        wsl('/bin/chmod', '600', '/root/peerloom-ci/redis.conf')
        launch(['wsl.exe', '--distribution', args.distro, '--exec',
                '/root/peerloom-ci/src/redis-server', '/root/peerloom-ci/redis.conf'], 'redis.log')
        deadline = time.monotonic() + 30
        while True:
            try:
                redis_ready(redisport, redispassword)
                break
            except (OSError, RuntimeError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.1)
        STAGE = 'build-native-windows-go'
        for name in ('device-server', 'device-migrate', 'device-bootstrap', 'device-admin'):
            run(['go', 'build', '-o', str(directory / (name + '.exe')), './cmd/' + name],
                cwd=root / 'src/device-server', env=env, timeout=300)
        STAGE = 'migrate-and-bootstrap-real-control-plane'
        run([str(directory / 'device-migrate.exe'), '--dir', str(root / 'infra/migrations'), 'up'], env=env)
        for filename, flags in (('registration.json', []),):
            with (directory / filename).open('xb') as out:
                run([str(directory / 'device-bootstrap.exe'), '--development', *flags], env=env, stdout=out)
        with (directory / 'admin.json').open('xb') as out:
            run([str(directory / 'device-admin.exe'), 'bootstrap', '--offline',
                 '--tenant-name', 'native-windows-ci', '--scope', 'admin'], env=env, stdout=out)
        server = launch([str(directory / 'device-server.exe')], 'server.log')
        origin = f'http://127.0.0.1:{httpport}'
        deadline = time.monotonic() + 30
        while True:
            if server.poll() is not None:
                raise RuntimeError('native Go exited before readiness')
            try:
                with urllib.request.urlopen(origin + '/readyz', timeout=2) as response:
                    if response.status == 200:
                        break
            except OSError:
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError('native Go readiness deadline')
            time.sleep(0.1)
        STAGE = 'management-create-authorized-pair'
        spec = importlib.util.spec_from_file_location('management_http', root / 'scripts/test-management.py')
        management = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(management)
        assert (directory / 'admin.json').stat().st_size <= 65536
        admin = json.loads((directory / 'admin.json').read_text())
        pair = create_authorized_pair(management.Client(origin), admin['service_credential'])
        private('pair.json', json.dumps(pair))
        stores = directory / 'stores'
        stores.mkdir()
        env.update(TEST_LEASE_ADMIN_FIXTURE=str(directory / 'admin.json'),
                   TEST_REGISTRATION_FIXTURE_FILE=str(directory / 'registration.json'),
                   TEST_SIGNAL_FIXTURE_FILE=str(directory / 'pair.json'),
                   TEST_NATIVE_STORE_ROOT=str(stores), TEST_IDENTITY_BASE_URL=origin)
        STAGE = 'native-sdk-dpapi-registration-authorized-pair-rotation'
        for test in ('native_registration_pair_rotation_and_close', 'native_secure_identity_survives_process_restart'):
            STAGE = test
            # Each command creates a NEW native Windows test process; never WSL/Wine.
            run(['cargo', '+1.99.1', 'test', '--manifest-path', str(root / 'src/device-sdk/Cargo.toml'),
                 '-p', 'device-core', '--test', 'windows_service', '--target', 'x86_64-pc-windows-msvc',
                 '--locked', test, '--', '--ignored', '--exact', '--nocapture'], env=env, timeout=300,
                stdout=None)
        evidence = root / 'dist/validation/windows-service.txt'
        evidence.parent.mkdir(parents=True, exist_ok=True)
        evidence_payload = ('Windows native Go + SDK + CurrentUser DPAPI: PASS\n'
                            'PostgreSQL 18.6 native Windows; Redis 8.10.3 in task-owned WSL1\n'
                            'Registration, approval, DTLS binary echo, credential rotation, persisted generation and both actual initial lease deadlines crossed and renewed, close gate, new-process reload: PASS\n')
    finally:
        cleanup_failed = False
        for process in reversed(children):
            try:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
            except Exception:
                cleanup_failed = True
        if pg_started:
            try:
                run([str(pg / 'pg_ctl.exe'), '-D', str(directory / 'data'), '-m', 'fast', '-w', 'stop'], env=env, timeout=30)
            except Exception:
                cleanup_failed = True
        if imported:
            try:
                run(['wsl.exe', '--terminate', args.distro], timeout=20)
            except Exception:
                # It may already have stopped, or import may not have completed.
                # Still attempt removal of exactly the task's admitted name.
                pass
            try:
                run(['wsl.exe', '--unregister', args.distro], timeout=30)
            except Exception:
                cleanup_failed = True
        for handle in handles:
            handle.close()
        if cleanup_failed:
            raise RuntimeError('owned process/distro cleanup failed')
    evidence.write_text(evidence_payload + 'Owned PostgreSQL/Redis/WSL cleanup: PASS\n')


def failure_summary(stage, error):
    status = ''
    if isinstance(error, urllib.error.HTTPError) and type(error.code) is int and 100 <= error.code <= 599:
        status = f' http_status={error.code}'
    return f'Windows service acceptance failed: stage={stage} category={type(error).__name__}{status}'


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(failure_summary(STAGE, error), file=sys.stderr)
        sys.exit(1)
