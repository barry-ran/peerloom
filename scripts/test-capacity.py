#!/usr/bin/env python3
# MIT — Copyright (c) 2026 Peerloom contributors.
"""独占本机 PG/Redis/Go + 单 PC/500 原生模拟 SDK 的真实容量验收，不下载、不改系统设置。"""
import argparse
import base64
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid

STAGE = 'preflight'
PRESENCE_COUNT_SCRIPT = "local n=0; for _,k in ipairs(redis.call('KEYS','peerloom:presence:*')) do if not string.match(k,':generation$') then n=n+1 end end; return n"
class Failure(Exception):
    """Only fixed labels / integer status may leave the private fixture."""


def require(condition, label):
    if not condition:
        raise Failure(label)


def private(path, data):
    with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0), 0o600), 'wb') as output:
        output.write(data if isinstance(data, bytes) else data.encode('utf-8'))


def evidence(path, value):
    private(path, json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def stop(process):
    if process.poll() is not None:
        return
    # Signal only the isolated process group created by this controller.
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def run(command, *, env=None, cwd=None, timeout=60):
    process = subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               stdin=subprocess.DEVNULL, start_new_session=True)
    try:
        stdout, _ = process.communicate(timeout=timeout)
    except BaseException as error:
        try:
            stop(process)
        finally:
            for stream in (process.stdout, process.stderr):
                if stream:
                    stream.close()
        if isinstance(error, subprocess.TimeoutExpired):
            raise Failure(Path(command[0]).name + ': timeout') from None
        raise
    if process.returncode:
        raise Failure(Path(command[0]).name + ': exit ' + str(process.returncode))
    return stdout


def free_port():
    with socket.socket() as connection:
        connection.bind(('127.0.0.1', 0))
        return connection.getsockname()[1]


def clean_env():
    env = dict(os.environ)
    for name in list(env):
        if name.startswith(('TEST_', 'PG', 'ADMIN_', 'TURN_', 'WEBHOOK_', 'REDIS_', 'RELAY_', 'DATABASE_', 'REPLAY_', 'LISTEN_', 'SIGNAL_', 'CREDENTIAL_', 'ROTATION_', 'DIRECT_')) or name in ('RUST_LOG', 'RUST_BACKTRACE', 'PEERLOOM_TEST_LEASE_DIAGNOSTICS'):
            env.pop(name, None)
    return env


def sdk_environment(fixture):
    # Only the test executable opts in; production builds omit test-diagnostics.
    env = clean_env()
    env['TEST_CAPACITY_FIXTURE'] = str(fixture)
    env['PEERLOOM_TEST_LEASE_DIAGNOSTICS'] = '1'
    return env


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def safe_progress(path):
    # Fixed enums and bounded numeric fields only. Keep the first failure even
    # when teardown emits hundreds of subsequent per-connection notifications.
    from collections import deque
    first, important, phases_seen, failures, tail = [], [], [], [], deque(maxlen=64)
    phases = r'(?:register|authorize|connect|baseline|hold|renewal-proof|pc-wss-reconnect|manual-new-sessions|explicit-session-close|shutdown)'
    unsigned, signed = r'[0-9]{1,16}', r'-?[0-9]{1,16}'
    patterns = (
        rf'capacity (?:ready_pairs=[0-9]{{1,3}}|phase={phases}(?: elapsed_ms={unsigned})?)',
        rf'capacity event=closed endpoint=[0-9]{{1,3}} reason=(?:closed|rejected|authorization_expired|transport|other) session_tag=[a-f0-9]{{16}}(?: elapsed_ms={unsigned})?',
        r'PeerloomTestDiag lease stage=(?:stale-generation|expired-before-update|expiry-conversion|maintenance-deadline|renewal-registration) current=[0-9]{1,20} incoming=[0-9]{1,20} own_ack=(?:true|false) pending=(?:true|false) remaining_ms=[0-9]{1,39}',
        rf'capacity baseline_complete elapsed_ms={unsigned} snapshot_elapsed_ms={unsigned} sessions=[0-9]{{1,3}}',
        rf'capacity lease_baseline endpoint=[0-9]{{1,3}} session_tag=[a-f0-9]{{16}} lease_generation={unsigned} baseline_elapsed_ms={unsigned} event_elapsed_ms={unsigned} snapshot_elapsed_ms={unsigned} source_baseline_remaining_ms={signed} target_baseline_remaining_ms={signed} source_event_remaining_ms={signed} target_event_remaining_ms={signed}',
    )
    if path.exists():
        with path.open('r', encoding='utf-8', errors='replace') as stream:
            for index, line in enumerate(stream):
                text = line.strip()
                if len(text) <= 2048 and any(re.fullmatch(pattern, text) for pattern in patterns):
                    accepted = text
                elif 'panicked at ' in text:
                    location = re.search(r'\bsdk_scale\.rs:([0-9]{1,6}):([0-9]{1,6})', text)
                    accepted = 'Rust assertion failed at sdk_scale.rs:' + ':'.join(location.groups()) if location else 'Rust assertion failed; private panic details withheld'
                else:
                    continue
                item = (index, accepted)
                if len(first) < 96:
                    first.append(item)
                if len(important) < 64 and accepted.startswith('PeerloomTestDiag lease '):
                    important.append(item)
                if len(phases_seen) < 24 and accepted.startswith(('capacity phase=', 'capacity baseline_complete ')):
                    phases_seen.append(item)
                if len(failures) < 8 and accepted.startswith(('capacity lease_baseline ', 'Rust assertion failed')):
                    failures.append(item)
                tail.append(item)
    # At most 256 summaries, independent of shutdown event count; original order.
    return [text for _, text in sorted(dict(first + important + phases_seen + failures + list(tail)).items())]


def versions(pg, redis):
    require(run([str(pg / 'postgres'), '--version']).decode().strip() == 'postgres (PostgreSQL) 18.6', 'PostgreSQL version mismatch')
    require(re.fullmatch(r'Redis server v=8\.10\.3 .*', run([str(redis / 'redis-server'), '--version']).decode().strip()) is not None, 'Redis version mismatch')


def redis_command(port, password, *arguments):
    def frame(values):
        return b'*' + str(len(values)).encode() + b'\r\n' + b''.join(b'$' + str(len(v)).encode() + b'\r\n' + v + b'\r\n' for v in values)
    with socket.create_connection(('127.0.0.1', port), timeout=3) as sock:
        sock.sendall(frame([b'AUTH', password.encode()]))
        require(sock.recv(64) == b'+OK\r\n', 'owned Redis auth failed')
        sock.sendall(frame([str(value).encode() for value in arguments]))
        data = sock.recv(65536)
        require(len(data) < 65536, 'Redis response bound')
        return data


def proc_stat(path):
    text = path.read_text()
    # comm may include spaces or closing parentheses; never read cmdline/environ.
    fields = text[text.rfind(')') + 2:].split()
    return {'ppid': int(fields[1]), 'ticks': int(fields[11]) + int(fields[12]),
            'threads': int(fields[17]), 'birth': int(fields[19]), 'rss': int(fields[21]) * os.sysconf('SC_PAGE_SIZE')}


def sample(roots):
    table = {}
    for directory in Path('/proc').iterdir():
        if directory.name.isdigit():
            try:
                table[int(directory.name)] = proc_stat(directory / 'stat')
            except (OSError, ValueError, IndexError):
                continue
    selected = {pid for pid in roots if pid in table}
    while True:
        more = {pid for pid, value in table.items() if value['ppid'] in selected}
        if more <= selected:
            break
        selected |= more
    result = {}
    for pid in selected:
        row = table[pid]
        try:
            row['fds'] = len(list(Path('/proc', str(pid), 'fd').iterdir()))
        except OSError:
            row['fds'] = 0
        result[str(pid)] = row
    return result


def memory_available():
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith('MemAvailable:'):
            return int(line.split()[1]) * 1024
    raise Failure('memory availability unreadable')


def measure(rows):
    values = list(rows.values())
    return {name: sum(value[name] for value in values) for name in ('rss', 'fds', 'threads')}


def cpu_delta(previous, current):
    return sum(max(0, row['ticks'] - previous.get(pid, {}).get('ticks', row['ticks']))
               for pid, row in current.items() if previous.get(pid, {}).get('birth') == row['birth']) / os.sysconf('SC_CLK_TCK')


def install_interrupt_handlers():
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    def interrupted(_sig, _frame):
        for sig in previous:
            signal.signal(sig, signal.SIG_IGN)
        raise Failure('controller interrupted')
    for sig in previous:
        signal.signal(sig, interrupted)
    return previous


def cleanup(children, logs):
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, signal.SIG_IGN)
    errors = []
    for process in reversed(children):
        try:
            stop(process)
        except (OSError, subprocess.SubprocessError):
            errors.append('owned-process-cleanup')
    for stream in logs:
        try:
            stream.close()
        except OSError:
            errors.append('owned-log-cleanup')
    if errors:
        raise Failure('cleanup failed: ' + ','.join(errors))


@contextlib.contextmanager
def private_workspace(output):
    directory = output / 'private'
    directory.mkdir(mode=0o700)
    try:
        yield directory
    except BaseException:
        # Local-only diagnostic retention; never include this directory in CI artifacts.
        # An operator deletes it after root-cause inspection. No automatic lost evidence.
        raise
    else:
        shutil.rmtree(directory)


def create_fixture(client, admin, peers, directory, origin):
    apps = []
    for label in ('PC', 'peers'):
        app = client.request('POST', '/v1/applications', 201, admin,
                             {'name': 'capacity-' + label, 'require_target_approval': True}, str(uuid.uuid4()))
        require(app.get('max_connections') == -1, 'server default application capacity is not unlimited')
        apps.append(app['id'])
    registrations = []
    for index in range(peers + 1):
        application = apps[0 if index == 0 else 1]
        grant = client.request('POST', '/v1/registration-grants', 201, admin,
                               {'application_id': application, 'expires_in_seconds': 3600}, str(uuid.uuid4()))
        registrations.append({'application_id': application, 'grant': grant['grant']})
    return {'origin': origin, 'registrations': registrations, 'service_credential': admin,
            'directory': str(directory), 'peer_count': peers, 'hold_seconds': 120}


def main():
    global STAGE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--pg-bin', type=Path, required=True)
    parser.add_argument('--redis-bin', type=Path, required=True)
    parser.add_argument('--server-bin', type=Path, required=True, help='already-built device-server/device-migrate/device-admin directory')
    parser.add_argument('--sdk-test', type=Path, required=True, help='already-built sdk_scale integration-test executable; no cargo build here')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--debug-close-only', action='store_true', help='<=20 peers, skips lease hold; never acceptance or a 500 pass')
    parser.add_argument('--source-manifest', type=Path, help='coordinator combined-tree manifest; recorded by digest, not claimed as a clean commit')
    parser.add_argument('--peers', type=int, default=500, help='1..500; smaller counts are smoke only, never a 500-capacity pass')
    args = parser.parse_args()
    require(sys.platform == 'linux' and os.getuid() != 0, 'unprivileged Linux required')
    require(1 <= args.peers <= 500, 'peer count bound')
    require(not args.debug_close_only or args.peers <= 20, 'debug-only mode cannot be a 500 acceptance')
    root, pg, redis, binaries, sdk_test = (path.resolve(strict=True) for path in (args.root, args.pg_bin, args.redis_bin, args.server_bin, args.sdk_test))
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    require(soft >= 4096, 'insufficient existing file-descriptor limit; no system changes made')
    require(memory_available() >= 3 * 1024**3, 'insufficient available memory before run')
    versions(pg, redis)
    args.output.mkdir(mode=0o700)
    output = args.output.resolve(strict=True)
    require(output.stat().st_uid == os.getuid() and stat.S_IMODE(output.stat().st_mode) == 0o700, 'private owned output required')
    spec = importlib.util.spec_from_file_location('capacity_management', root / 'scripts/test-management.py')
    management = importlib.util.module_from_spec(spec); spec.loader.exec_module(management)
    env = clean_env(); children, logs, samples = [], [], []
    started = None; cpu_seconds = 0.0; peak = {'rss': 0, 'fds': 0, 'threads': 0}
    result = {'status': 'failed', 'requested_peers': args.peers, 'physical_android_devices': False,
              'sdk_test_sha256': digest(sdk_test), 'tested_source_status': 'combined-working-tree-not-claimed-clean-commit',
              'source_manifest_sha256': digest(args.source_manifest.resolve(strict=True)) if args.source_manifest else None,
              'cpu_count': os.cpu_count(), 'nofile_soft': soft, 'nofile_hard': hard, 'rss_measurement': 'sum of owned process RSS; shared pages may be counted more than once',
              'source_inputs': {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in ('src/device-sdk/Cargo.lock', 'src/device-server/go.sum', 'src/device-sdk/device-core/src/sdk.rs', 'src/device-sdk/device-core/tests/sdk_scale.rs')},
              'binary_sha256': {name: digest(binaries / name) for name in ('device-server', 'device-admin', 'device-migrate')}}
    with private_workspace(output) as private_dir:
        def launch(command, label, selected_env=env):
            stream = (private_dir / (label + '.log')).open('xb'); os.fchmod(stream.fileno(), 0o600); logs.append(stream)
            process = subprocess.Popen(command, env=selected_env, stdout=stream, stderr=subprocess.STDOUT,
                                       stdin=subprocess.DEVNULL, start_new_session=True)
            children.append(process)
            return process
        try:
            ports = set()
            while len(ports) < 3:
                ports.add(free_port())
            pgport, redisport, httpport = sorted(ports)
            password, redis_password = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            private(private_dir / 'pg-password', password)
            private(private_dir / 'redis-password', redis_password)
            private(private_dir / 'database-url', f'postgres://peerloom_capacity:{password}@127.0.0.1:{pgport}/postgres?sslmode=disable')
            private(private_dir / 'replay-key', base64.b64encode(secrets.token_bytes(32)))
            private(private_dir / 'pgpass', f'127.0.0.1:{pgport}:postgres:peerloom_capacity:{password}\n')
            env.update(DATABASE_URL_FILE=str(private_dir / 'database-url'), REPLAY_KEY_FILE=str(private_dir / 'replay-key'),
                       REDIS_PASSWORD_FILE=str(private_dir / 'redis-password'), REDIS_ADDRESS=f'127.0.0.1:{redisport}', LISTEN_ADDRESS=f'127.0.0.1:{httpport}')
            STAGE = 'initialize-owned-pgdata'
            run([str(pg / 'initdb'), '-D', str(private_dir / 'pgdata'), '-U', 'peerloom_capacity',
                 '--auth-host=scram-sha-256', '--auth-local=reject', '--pwfile=' + str(private_dir / 'pg-password'), '--no-locale', '--encoding=UTF8'], env=env)
            postgres = launch([str(pg / 'postgres'), '-D', str(private_dir / 'pgdata'), '-h', '127.0.0.1', '-p', str(pgport), '-k', ''], 'postgres')
            private(private_dir / 'redis.conf', f'bind 127.0.0.1\nport {redisport}\nprotected-mode yes\nrequirepass {redis_password}\nsave ""\nappendonly no\ndir {private_dir}\n')
            cache = launch([str(redis / 'redis-server'), str(private_dir / 'redis.conf')], 'redis')
            STAGE = 'owned-dependencies-ready'; deadline = time.monotonic() + 30
            while True:
                require(postgres.poll() is None and cache.poll() is None, 'owned dependency exited')
                try:
                    run([str(pg / 'pg_isready'), '-h', '127.0.0.1', '-p', str(pgport)], env=env, timeout=3)
                    require(redis_command(redisport, redis_password, 'PING') == b'+PONG\r\n', 'Redis ping failed')
                    break
                except (OSError, Failure):
                    require(time.monotonic() < deadline, 'owned readiness timeout'); time.sleep(.1)
            STAGE = 'migrate-bootstrap'
            run([str(binaries / 'device-migrate'), '--dir', str(root / 'infra/migrations'), 'up'], env=env)
            admin = json.loads(run([str(binaries / 'device-admin'), 'bootstrap', '--offline', '--tenant-name', 'capacity-private', '--scope', 'admin'], env=env))['service_credential']
            server = launch([str(binaries / 'device-server')], 'server')
            origin = f'http://127.0.0.1:{httpport}/'; client = management.Client(origin)
            deadline = time.monotonic() + 30
            while True:
                require(server.poll() is None, 'Go server exited before ready')
                try:
                    client.request('GET', '/v1/applications', 200, admin); break
                except (OSError, management.CheckFailure):
                    require(time.monotonic() < deadline, 'server readiness timeout'); time.sleep(.1)
            STAGE = 'provision-registration-grants'
            fixture = create_fixture(client, admin, args.peers, output, origin)
            fixture['debug_close_only'] = args.debug_close_only
            if args.debug_close_only: fixture['hold_seconds'] = 0
            private(private_dir / 'fixture.json', json.dumps(fixture))
            STAGE = 'real-sdk-capacity'
            test_env = sdk_environment(private_dir / 'fixture.json')
            sdk = launch([str(sdk_test), '--ignored', '--exact', 'one_pc_five_hundred_real_native_peers', '--nocapture'], 'sdk', test_env)
            started = time.monotonic(); previous = {}; cpu_seconds = 0.0; peak = {'rss': 0, 'fds': 0, 'threads': 0}
            baseline_presence_checked = False
            while sdk.poll() is None:
                require(all(process.poll() is None for process in (postgres, cache, server)), 'owned dependency exited during stress')
                require(time.monotonic() - started < 1200, 'whole stress deadline')
                if not baseline_presence_checked and (output / 'baseline.json').exists():
                    require(redis_command(redisport, redis_password, 'EVAL', PRESENCE_COUNT_SCRIPT, '0') == (':' + str(args.peers + 1) + '\r\n').encode(), 'baseline Redis must contain each SDK identity once')
                    baseline_presence_checked = True
                    result['redis_active_presence_at_ready_barrier'] = args.peers + 1
                rows = sample([process.pid for process in children]); measured = measure(rows)
                cpu_seconds += cpu_delta(previous, rows); previous = rows
                peak = {name: max(peak[name], value) for name, value in measured.items()}
                samples.append({'elapsed_seconds': round(time.monotonic() - started, 3), **measured, 'cpu_seconds': round(cpu_seconds, 3)})
                require(measured['rss'] <= 7 * 1024**3 and memory_available() >= 512 * 1024**2, 'resource watchdog: memory bound')
                time.sleep(1)
            require(sdk.returncode == 0, 'sdk_scale exit ' + str(sdk.returncode))
            require(baseline_presence_checked or args.debug_close_only, 'missing baseline online identity proof')
            STAGE = 'verify-closed-resources'
            proof = json.loads((output / 'sdk-proof.json').read_text())
            require(proof.get('status') == ('debug-only' if args.debug_close_only else 'passed') and proof.get('simultaneous_ready') == args.peers, 'missing real capacity proof')
            if not args.debug_close_only:
                require(proof.get('hold_seconds', 0) >= 120 and proof.get('all_initial_dual_deadlines_crossed_and_renewed') is True, 'missing real lease crossing proof')
            # Snapshot directly from this new isolated database: never supplied DSN/production DB.
            pgenv = dict(clean_env(), PGHOST='127.0.0.1', PGPORT=str(pgport), PGUSER='peerloom_capacity', PGDATABASE='postgres', PGPASSFILE=str(private_dir / 'pgpass'))
            sql = "SELECT json_build_object('devices',(SELECT count(*) FROM devices),'sessions',(SELECT count(*) FROM sessions),'not_closed',(SELECT count(*) FROM sessions WHERE state <> 'closed'));"
            database = json.loads(run([str(pg / 'psql'), '-X', '-At', '-c', sql], env=pgenv))
            require(database['devices'] == args.peers + 1 and database['sessions'] == args.peers + min(args.peers, 20) and database['not_closed'] == 0, 'database identity/session close evidence mismatch')
            # Only owned Redis is queried; generation counters are deliberately not active presence.
            deadline = time.monotonic() + 10
            while redis_command(redisport, redis_password, 'EVAL', PRESENCE_COUNT_SCRIPT, '0') != b':0\r\n':
                require(time.monotonic() < deadline, 'active Redis presence remained after SDK shutdown'); time.sleep(.1)
            result.update(status='debug-only' if args.debug_close_only else ('passed' if args.peers == 500 else 'smoke-passed-not-500'), sdk=proof, database=database,
                          redis_active_presence_after_close=0, elapsed_seconds=round(time.monotonic()-started,3), peak=peak,
                          cpu_seconds=round(cpu_seconds,3), samples=len(samples))
        except BaseException as error:
            if started is not None:
                result.update(elapsed_seconds=round(time.monotonic() - started, 3), peak=peak,
                              cpu_seconds=round(cpu_seconds, 3), samples=len(samples))
            result['failure_stage'] = STAGE
            result['failure'] = str(error) if isinstance(error, Failure) else type(error).__name__
            raise
        finally:
            try:
                cleanup(children, logs)
                result['owned_processes_reaped'] = all(process.poll() is not None for process in children)
            except BaseException:
                result['status'] = 'failed'
                result['cleanup_failed'] = True
                raise
            finally:
                result['private_failure_logs_retained'] = result['status'] == 'failed'
                result['sdk_progress'] = safe_progress(private_dir / 'sdk.log')
                evidence(output / 'resource-samples.json', samples)
                evidence(output / 'capacity-result.json', result)
    print('capacity acceptance: ' + result['status'])
    return 0


if __name__ == '__main__':
    previous = install_interrupt_handlers()
    try:
        sys.exit(main())
    except Exception as error:
        label = str(error) if isinstance(error, Failure) else type(error).__name__
        print('Capacity failed at ' + STAGE + ': ' + label + '; private output withheld.', file=sys.stderr)
        sys.exit(1)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
