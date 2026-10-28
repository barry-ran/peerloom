#!/usr/bin/env python3
"""创建自己的随机 PGDATA/loopback 端口跑当前全部迁移备份验收；绝不使用外部 PGDATA。"""
import argparse
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(args, env, *, timeout=120):
    try:
        result = subprocess.run(args, env=env, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError('isolated PostgreSQL command unavailable or timed out') from None
    if result.returncode:
        raise RuntimeError('isolated PostgreSQL command failed; secret-bearing output withheld')
    return result.stdout


def isolated():
    if os.geteuid() == 0:
        raise RuntimeError('run as the dedicated non-root test user')
    migrate = Path(os.environ['PEERLOOM_TEST_MIGRATE_BIN']).resolve(strict=True)
    # Inherited libpq configuration and production DSNs cannot redirect this fixture.
    env = {k: v for k, v in os.environ.items() if not k.startswith('PG') and k not in ('DATABASE_URL', 'DATABASE_URL_FILE', 'TEST_DATABASE_URL')}
    with tempfile.TemporaryDirectory(prefix='peerloom-backup-cluster-') as temporary:
        base = Path(temporary)
        base.chmod(0o700)
        data = base / 'pgdata'
        password = secrets.token_hex(32)
        secret = base / 'password'
        secret.write_text(password + '\n'); secret.chmod(0o600)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        passfile = base / 'pgpass'
        passfile.write_text(f'127.0.0.1:{port}:*:peerloom_fixture:{password}\n'); passfile.chmod(0o600)
        env.update(PGHOST='127.0.0.1', PGPORT=str(port), PGUSER='peerloom_fixture', PGDATABASE='postgres', PGPASSFILE=str(passfile),
                   PEERLOOM_BACKUP_INTEGRATION='1', PEERLOOM_TEST_MIGRATE_BIN=str(migrate))
        run(['initdb', '-D', str(data), '-U', 'peerloom_fixture', '--encoding=UTF8', '--locale=C',
             '--auth-local=scram-sha-256', '--auth-host=scram-sha-256', '--pwfile', str(secret)], env)
        try:
            run(['pg_ctl', '-D', str(data), '-l', str(base / 'postgres.log'), '-w', '-t', '30',
                 '-o', f"-h 127.0.0.1 -p {port} -c unix_socket_directories=''", 'start'], env, timeout=40)
            # Existing integration suite applies every current migration in a fresh source DB.
            result = subprocess.run(['python3', str(ROOT / 'scripts/test-postgres-backup.py')], env=env, timeout=180)
            if result.returncode:
                raise RuntimeError('current-schema backup/restore integration failed')
            migrations = sorted(p.name for p in (ROOT / 'infra/migrations').glob('*.up.sql'))
            print(json.dumps({'scope': 'isolated-postgresql-logical-backup', 'migration_files': migrations,
                              'postgres': run(['pg_dump', '--version'], env).decode().strip(),
                              'shared_pgdata_used': False, 'external_database_used': False}, ensure_ascii=False))
        finally:
            # Only our newly initialized directory is ever addressed. If startup partially
            # succeeded, stop it too; an absent server has no PID file and needs no signal.
            if (data / 'postmaster.pid').exists():
                run(['pg_ctl', '-D', str(data), '-w', '-t', '30', '-m', 'fast', 'stop'], env, timeout=40)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-isolated', action='store_true')
    args = parser.parse_args()
    if not args.run_isolated:
        parser.error('requires explicit --run-isolated')
    os.umask(0o077)
    try:
        isolated()
    except (RuntimeError, KeyError, FileNotFoundError) as error:
        if isinstance(error, RuntimeError):
            raise SystemExit(str(error)) from None
        raise SystemExit('isolated test migration binary is required') from None


if __name__ == '__main__':
    main()
