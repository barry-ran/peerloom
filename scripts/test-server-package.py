#!/usr/bin/env python3
# MIT — Copyright (c) 2026 Peerloom contributors.
"""仅从服务端交付 tar 构建隔离 runtime；不向 Docker 提供仓库或编译器。"""
import argparse
import functools
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import signal
import subprocess
import tarfile
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
BINS = ('device-server', 'device-migrate', 'device-bootstrap', 'device-admin', 'device-admin-user')
MIGRATIONS = ('initial', 'identity_replay', 'session_authorization', 'tenant_management',
              'managed_relay', 'browser_administration', 'direct_registration',
              'session_recovery', 'webhook_delivery')
SQL = tuple(f'infra/migrations/{i:06}_{name}.{direction}.sql'
            for i, name in enumerate(MIGRATIONS, 1) for direction in ('up', 'down'))


class Failure(Exception):
    pass


def invoke(args, *, data=None, capture=False, timeout=180, env=None):
    # No argument, stdout/stderr or exception text is logged: fixtures contain secrets.
    process = subprocess.Popen(args, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                               stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, env=env, start_new_session=True)
    try:
        output, _ = process.communicate(data, timeout=timeout)
    except BaseException:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=10)
        raise
    if process.returncode:
        raise Failure('controlled command failed: ' + str(process.returncode))
    if capture and len(output) > 65536:
        raise Failure('controlled output limit')
    return output if capture else b''


def extract(payload, root):
    seen, total = set(), 0
    with tarfile.open(payload, 'r:gz') as archive:
        for member in archive:
            name = member.name
            parts = PurePosixPath(name).parts
            if (not member.isfile() or name in seen or not parts or name != '/'.join(parts)
                    or name.startswith('/') or any(p in ('.', '..') for p in parts)
                    or '\\' in name or '\x00' in name or member.mode & 0o7022
                    or name.startswith(('src/', 'sdk/', '.secrets/', '.git/'))
                    or name.endswith(('.go', '.rs', '.kt', '.swift', '.c', '.cpp'))):
                raise Failure('unsafe or source-bearing package member')
            total += member.size
            if member.size < 0 or total > 512 * 1024 * 1024 or len(seen) >= 4096:
                raise Failure('package bound exceeded')
            seen.add(name)
            destination = root.joinpath(*parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as source, destination.open('xb') as target:
                remaining = member.size
                while remaining:
                    chunk = source.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise Failure('truncated package member')
                    target.write(chunk)
                    remaining -= len(chunk)
            destination.chmod(member.mode & 0o777)
    required = {'bin/' + name for name in BINS} | set(SQL) | {
        'deploy/Dockerfile', 'deploy/Dockerfile.dockerignore', 'deploy/init-private.py',
        'deploy/compose.yaml', 'deploy/compose.tls.yaml', 'deploy/gateway/nginx-tls.conf',
        'SHA256SUMS'}
    if not required <= seen:
        raise Failure('incomplete server package')
    checksums = {}
    for line in (root / 'SHA256SUMS').read_text().splitlines():
        value, name = line.split('  ', 1)
        if name in checksums or name not in seen or len(value) != 64:
            raise Failure('invalid inner checksum manifest')
        checksums[name] = value
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != value:
            raise Failure('inner checksum mismatch')
    if set(checksums) != seen - {'SHA256SUMS'}:
        raise Failure('incomplete checksum coverage')
    for name in BINS:
        if (root / 'bin' / name).stat().st_mode & 0o111 != 0o111:
            raise Failure('binary executable mode lost')


def remove_owned_container(run, name):
    # UUID-owned exact names only; never prune or remove arbitrary daemon resources.
    import re
    if not re.fullmatch(r'peerloom-package-[0-9a-f]{32}-(image-probe|egress-target|egress-client-[0-9]+|oneoff-[0-9]+)', name):
        raise Failure('invalid owned resource name')
    present = run(['docker', 'container', 'ls', '-a', '--filter', 'name=^/' + name + '$',
                   '--format', '{{.Names}}'], capture=True).decode().strip()
    if present:
        if present != name:
            raise Failure('resource ownership mismatch')
        run(['docker', 'container', 'rm', '-f', name], timeout=30)


def remove_owned_image(run, image):
    import re
    if not re.fullmatch(r'peerloom-package-[0-9a-f]{32}:runtime', image):
        raise Failure('invalid owned image name')
    present = run(['docker', 'image', 'ls', '--filter', 'reference=' + image,
                   '--format', '{{.Repository}}:{{.Tag}}'], capture=True).decode().strip()
    if present:
        if present != image:
            raise Failure('image ownership mismatch')
        run(['docker', 'image', 'rm', image], timeout=30)


def verify_egress(run, client, directory, package, project, image, server_id, gateway_image, owned):
    import time
    probe = directory / 'egress-client'
    # Client-only build: never in the package root, Docker build context, or release artifact.
    invoke(['go', 'build', '-trimpath', '-o', str(probe), str(ROOT / 'scripts/server-egress-probe.go')],
           env=dict(os.environ, CGO_ENABLED='0'), timeout=120)
    probe.chmod(0o555)  # New nonsecret CI client only; runnable by image UID65532 despite umask077.
    wrong_ca = client.certificates(directory / 'wrong-tls')
    for ca in (directory / 'tls/ca.crt', wrong_ca):
        ca.chmod(0o444)  # Own synthetic public CA only; original operator files are never changed.
    config = directory / 'egress-nginx.conf'
    config.write_text('pid /tmp/nginx.pid; error_log /dev/stderr warn; events {} '
                     'http { access_log off; client_body_temp_path /tmp/client_temp; proxy_temp_path /tmp/proxy_temp; '
                     'fastcgi_temp_path /tmp/fastcgi_temp; uwsgi_temp_path /tmp/uwsgi_temp; scgi_temp_path /tmp/scgi_temp; '
                     'server { listen 8443 ssl; '
                     'ssl_certificate /fixture/certificate.pem; ssl_certificate_key /fixture/private-key.pem; '
                     'ssl_protocols TLSv1.2 TLSv1.3; location = /healthz { return 200 "egress-ok"; } } }')
    config.chmod(0o444)
    target = project + '-egress-target'
    owned.append(target)
    run(['docker', 'run', '-d', '--name', target, '--network', project + '_egress',
         '--user', '65532:65532', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
         '--tmpfs', '/tmp', '--health-cmd', 'test -s /tmp/nginx.pid', '--health-interval', '1s',
         '--health-timeout', '1s', '--health-retries', '10',
         '--mount', 'type=bind,src=' + str(config) + ',dst=/etc/nginx/nginx.conf,readonly',
         '--mount', 'type=bind,src=' + str(package / '.tls/certificate.pem') + ',dst=/fixture/certificate.pem,readonly',
         '--mount', 'type=bind,src=' + str(package / '.tls/private-key.pem') + ',dst=/fixture/private-key.pem,readonly',
         '--entrypoint', 'nginx', gateway_image, '-g', 'daemon off;'])
    deadline = time.monotonic() + 15
    while True:
        health = run(['docker', 'inspect', '--format', '{{.State.Health.Status}}', target], capture=True).strip()
        if health == b'healthy':
            break
        if health == b'unhealthy' or time.monotonic() >= deadline:
            raise Failure('owned egress fixture not ready')
        time.sleep(0.25)
    network = json.loads(run(['docker', 'inspect', '--format', '{{json .NetworkSettings.Networks}}', target], capture=True))
    address = network[project + '_egress']['IPAddress']
    for number, ca in enumerate((directory / 'tls/ca.crt', wrong_ca)):
        name = project + '-egress-client-' + str(number)
        owned.append(name)
        args = ['docker', 'run', '--rm', '--name', name, '--network', 'container:' + server_id,
                '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                '--mount', 'type=bind,src=' + str(probe) + ',dst=/fixture/client,readonly',
                '--mount', 'type=bind,src=' + str(ca) + ',dst=/fixture/ca.pem,readonly',
                '--entrypoint', '/fixture/client', image, '--address', address, '--ca', '/fixture/ca.pem']
        if number:
            args.append('--reject')
        run(args, timeout=20)


def safe_diagnostic(error):
    # Only our controlled Failure strings are safe; external exception text may contain credentials.
    return str(error) if isinstance(error, Failure) else type(error).__name__


def interrupted(_signum, _frame):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    raise Failure('interrupted; cleaning owned fixture')


def execute(payload, client=None):
    if client is None:
        spec = importlib.util.spec_from_file_location('tls_client', ROOT / 'scripts/test-tls-compose.py')
        client = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(client)
    client.require_local_docker()
    project = 'peerloom-package-' + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix=project + '-') as temporary:
        directory = Path(temporary)
        package = directory / 'package'
        package.mkdir(mode=0o700)
        extract(payload, package)
        # Test helpers remain outside the context; all executables/config/SQL below are delivered bytes.
        invoke(['python3', str(package / 'deploy/init-private.py')])
        ca = client.certificates(directory / 'tls')
        original_key = directory / 'tls/server.key'
        original_key.chmod(0o600)  # Own synthetic fixture only; exercise ordinary private source input.
        before_key = (original_key.stat().st_ino, original_key.stat().st_mode,
                      hashlib.sha256(original_key.read_bytes()).hexdigest())
        invoke(['python3', str(package / 'deploy/init-private.py'), '--stage-tls',
                '--certificate', str(directory / 'tls/server.crt'), '--private-key', str(original_key)])
        if before_key != (original_key.stat().st_ino, original_key.stat().st_mode,
                          hashlib.sha256(original_key.read_bytes()).hexdigest()):
            raise Failure('TLS source unexpectedly changed')
        environment = dict(os.environ, TLS_ADMIN_ORIGIN=client.ORIGIN)
        compose = ['docker', 'compose', '-p', project, '-f', str(package / 'deploy/compose.yaml'),
                   '-f', str(package / 'deploy/compose.tls.yaml')]
        run = functools.partial(invoke, env=environment)
        image = project + ':runtime'
        # Only tag differs; context and deployed configuration remain the package's actual templates.
        override = directory / 'image.json'
        override.write_text(json.dumps({'services': {name: {'image': image}
                            for name in ('device-server', 'migrate')}}))
        compose += ['-f', str(override)]
        stage, build_attempted = 'render', False
        owned = []
        def oneoff(service, arguments, *, entrypoint=None, data=None, capture=False):
            name = project + '-oneoff-' + str(len(owned))
            owned.append(name)  # Register before daemon mutation, including unknown outcomes.
            command = compose + ['run', '--rm', '-T', '--no-deps', '--name', name]
            if entrypoint:
                command += ['--entrypoint', entrypoint]
            return run(command + [service] + arguments, data=data, capture=capture)
        try:
            # Include the tools-profile migrate service for the two-context security assertion.
            # Normal up still names only runtime services; this flag affects config inspection only.
            rendered = run(compose + ['--profile', 'tools', 'config', '--format', 'json'], capture=True)
            client.validate_rendered(rendered)
            config = json.loads(rendered)
            for name in ('device-server', 'migrate'):
                if Path(config['services'][name]['build']['context']).resolve() != package:
                    raise Failure('build context escaped extracted package')
            stage = 'runtime build'
            build_attempted = True
            run(compose + ['build', 'device-server'], timeout=300)
            # Image contains no source or build toolchain; CA store must support ordinary outbound TLS.
            probe_name = project + '-image-probe'
            owned.append(probe_name)
            run(['docker', 'run', '--rm', '--name', probe_name, '--network', 'none', '--entrypoint', 'sh', image, '-ec',
                 'test -s /etc/ssl/cert.pem; for x in go cargo rustc node npm; do ! command -v "$x"; done; test ! -e /src'])
            stage = 'least-privilege secret mounts'
            for service, check in {
                'device-server': 'test -r /run/secrets/database_url; test -r /run/secrets/replay_key; test -r /run/secrets/redis_password; test ! -e /run/secrets/postgres_password; test ! -e /run/secrets/redis_config',
                'migrate': 'test -r /run/secrets/database_url; test ! -e /run/secrets/replay_key; test ! -e /run/secrets/redis_password',
                'gateway': 'test -r /run/secrets/tls_private_key; test ! -e /run/secrets/database_url; test ! -e /run/secrets/replay_key',
            }.items():
                allowed = {'device-server': 'database_url replay_key redis_password',
                           'migrate': 'database_url', 'gateway': 'tls_certificate tls_private_key'}[service]
                readonly = ('for name in ' + allowed + '; do f=/run/secrets/$name; '
                            'test ! -w "$f"; before="$(cksum "$f")"; '
                            'if (printf forbidden >> "$f") 2>/dev/null; then exit 1; fi; '
                            'test "$before" = "$(cksum "$f")"; done')
                oneoff(service, ['-ec', 'test "$(id -u)" != 0; ' + check + '; ' + readonly], entrypoint='sh')
            stage = 'database and schema 10'
            run(compose + ['up', '-d', '--wait', 'postgres', 'redis'])
            oneoff('migrate', [])
            versions = run(compose + ['exec', '-T', 'postgres', 'psql', '-U', 'peerloom', '-d', 'peerloom',
                           '-Atc', 'SELECT string_agg(version::text,\',\' ORDER BY version) FROM schema_migrations'], capture=True)
            if versions.strip() != b'1,2,3,4,5,6,7,8,9,10':
                raise Failure('migration versions mismatch')
            stage = 'explicit isolated fixture accounts'
            pair = json.loads(oneoff('device-server', ['--development', '--pair'], entrypoint='device-bootstrap', capture=True))
            bootstrap = json.loads(oneoff('migrate', ['bootstrap', '--offline', '--tenant-name', 'isolated-package',
                '--scope', 'admin', '--ttl', '24h', '--label', 'package-acceptance'], entrypoint='device-admin', capture=True))
            tenant = str(uuid.UUID(bootstrap['tenant_id']))
            password = 'Synthetic package admin ' + secrets.token_urlsafe(32)
            created = json.loads(oneoff('migrate', ['create', '--offline', '--tenant-id', tenant,
                '--username', 'gateway_owner', '--scope', 'admin', '--password-stdin'], entrypoint='device-admin-user',
                data=(password + '\n').encode(), capture=True))
            if created.get('status') != 'created':
                raise Failure('fixture account creation failed')
            stage = 'HTTPS admin and authenticated WSS'
            run(compose + ['up', '-d', '--wait', 'device-server', 'gateway'])
            # Runtime network inspection proves the deployment wiring, not arbitrary public reachability.
            identifiers = run(compose + ['ps', '-q', 'device-server'], capture=True).decode().strip()
            networking = json.loads(run(['docker', 'inspect', '--format', '{{json .NetworkSettings.Networks}}',
                                         identifiers], capture=True))
            if set(networking) != {project + '_backend', project + '_egress'}:
                raise Failure('server egress network missing or unexpected')
            network = json.loads(run(['docker', 'network', 'inspect', '--format', '{{json .Internal}}',
                                      project + '_egress'], capture=True))
            if network is not False:
                raise Failure('server egress incorrectly internal')
            stage = 'controlled HTTPS egress and wrong-CA rejection'
            verify_egress(run, client, directory, package, project, image, identifiers,
                          config['services']['gateway']['image'], owned)
            stage = 'HTTPS admin and authenticated WSS'
            client.verify_default_trust_rejects()
            client.verify_https(tenant, password, ca)
            client.verify_wss(pair['source']['device_credential'], ca)
        except Exception as error:
            raise Failure('packaged server acceptance failed at ' + stage + ': ' + type(error).__name__) from None
        finally:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            cleanup_errors = []
            for name in owned:
                try:
                    remove_owned_container(run, name)
                except Exception:
                    cleanup_errors.append('container')
            try:
                run(compose + ['down', '--volumes', '--remove-orphans', '--timeout', '10'], timeout=90)
            except Exception:
                cleanup_errors.append('compose')
            if build_attempted:
                try:
                    remove_owned_image(run, image)
                except Exception:
                    cleanup_errors.append('image')
            if cleanup_errors:
                raise Failure('owned fixture cleanup failed')
    print('实际 server tar：无源码 runtime、10版迁移、HTTPS admin 登录/CSRF、认证 WSS heartbeat 通过。')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        execute(args.package)
    except Exception as error:
        raise SystemExit('server package acceptance failed: ' + safe_diagnostic(error)) from None


if __name__ == '__main__':
    main()
