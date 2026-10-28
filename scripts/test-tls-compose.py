#!/usr/bin/env python3
# MIT — Copyright (c) 2026 Peerloom contributors.
"""仅新建隔离 Compose 的真实 HTTPS/WSS/管理后台验收；不部署或修改系统信任。"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import functools
import http.cookiejar
import importlib.util
import json
import os
import re
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import struct
import tempfile
import urllib.error
import urllib.request
import uuid

import yaml

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = 'https://127.0.0.1:18443'


class Failure(Exception):
    pass


class ToolFailure(Failure):
    """Only controlled category; never carries command arguments or captured output."""


def invoke(args, *, data=None, capture=False, timeout=180, env=None):
    tool = Path(args[0]).name
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", tool):
        tool = "tool"
    try:
        result = subprocess.run(args, env=env, input=data, stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise ToolFailure('command=' + tool + '; outcome=timeout') from None
    except OSError:
        raise ToolFailure('command=' + tool + '; outcome=unavailable') from None
    if result.returncode:
        raise ToolFailure('command=' + tool + '; exit_code=' + str(result.returncode))
    if capture and len(result.stdout) > 16384:
        raise ToolFailure('command=' + tool + '; outcome=output_limit')
    return result.stdout if capture else b''


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Failure('refusing redirect of authenticated fixture request')


def certificates(directory):
    directory.mkdir(mode=0o700)
    invoke(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=Peerloom Synthetic Test CA', '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
            '-keyout', str(directory / 'ca.key'), '-out', str(directory / 'ca.crt')])
    invoke(['openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost',
            '-keyout', str(directory / 'server.key'), '-out', str(directory / 'server.csr')])
    extensions = directory / 'server.ext'
    extensions.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n')
    invoke(['openssl', 'x509', '-req', '-in', str(directory / 'server.csr'), '-CA', str(directory / 'ca.crt'),
            '-CAkey', str(directory / 'ca.key'), '-CAcreateserial', '-days', '1', '-sha256',
            '-extfile', str(extensions), '-out', str(directory / 'server.crt')])
    # Only synthetic leaf material is mounted. Compose bind-secrets do not remap owner.
    # Host directory remains 0700; the non-root gateway requires read-only file access.
    for name in ('server.key', 'server.crt'):
        (directory / name).chmod(0o444)
    (directory / 'ca.key').chmod(0o600)
    return directory / 'ca.crt'


def configuration(root, directory, project):
    config = yaml.safe_load((root / 'infra/compose.yaml').read_text())
    config['name'] = project
    services = config['services']
    image = project + ':validation'
    for name in ('device-server', 'migrate'):
        services[name]['image'] = image
        services[name]['build']['context'] = str(root)
    if services['gateway']['ports'] != ['127.0.0.1:18080:8080'] or services['postgres'].get('ports') or services['redis'].get('ports'):
        raise Failure('refusing unexpected original public ports')
    for name, value in config['secrets'].items():
        if name not in ('postgres_password', 'database_url', 'redis_password', 'redis_config', 'replay_key'):
            raise Failure('unknown fixture secret')
        value['file'] = str(directory / '.secrets' / name)
    server = config['services']['device-server']
    server['environment'].update(ADMIN_ORIGIN=ORIGIN, ADMIN_DEVELOPMENT_LOOPBACK='')
    gateway = config['services']['gateway']
    gateway['ports'] = ['127.0.0.1:18443:8443']
    gateway['volumes'] = [str(root / 'infra/gateway/nginx-tls.conf') + ':/etc/nginx/nginx.conf:ro']
    gateway['secrets'] = ['tls_certificate', 'tls_private_key']
    config['secrets']['tls_certificate'] = {'file': str(directory / 'tls/server.crt')}
    config['secrets']['tls_private_key'] = {'file': str(directory / 'tls/server.key')}
    return config, image


def validate_rendered(raw):
    config = json.loads(raw)
    services = config['services']
    ports = services['gateway'].get('ports', [])
    if len(ports) != 1 or ports[0].get('host_ip') != '127.0.0.1' or str(ports[0].get('published')) != '18443' or ports[0].get('target') != 8443:
        raise Failure('rendered TLS fixture may publish beyond its own loopback port')
    if any(value.get('ports') for name, value in services.items() if name != 'gateway'):
        raise Failure('rendered TLS fixture unexpectedly exposes a backend')
    environment = services['device-server']['environment']
    if environment.get('ADMIN_ORIGIN') != ORIGIN or environment.get('ADMIN_DEVELOPMENT_LOOPBACK'):
        raise Failure('rendered gateway is not in HTTPS cookie mode')


def verify_https(tenant, password, ca, origin=ORIGIN):
    context = ssl.create_default_context(cafile=str(ca))
    jar = http.cookiejar.CookieJar()
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
        urllib.request.HTTPSHandler(context=context), urllib.request.HTTPCookieProcessor(jar))

    def call(path, *, method='GET', data=None, headers=None, status=200):
        values = dict(headers or {})
        body = None if data is None else json.dumps(data).encode()
        if body is not None:
            values['Content-Type'] = 'application/json'
        request = urllib.request.Request(origin + path, data=body, headers=values, method=method)
        try:
            response = client.open(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(1_048_577)
            if response.status != status or len(raw) > 1_048_576:
                raise Failure('HTTPS status/body bound mismatch: ' + path)
            return raw, response.headers

    page, headers = call('/admin/')
    if b'Peerloom' not in page or "script-src 'self'" not in headers.get('Content-Security-Policy', ''):
        raise Failure('HTTPS management page/CSP missing')
    call('/readyz')
    call('/metrics', status=404)
    call('/v1/device-signal', status=401)
    login = {'tenant_id': tenant, 'username': 'gateway_owner', 'password': password}
    call('/admin/api/auth/login', method='POST', data=login, headers={'Origin': 'https://invalid.example'}, status=403)
    call('/admin/api/auth/login', method='POST', data=login, headers={'Origin': origin, 'Host': 'invalid.example'}, status=403)
    body, headers = call('/admin/api/auth/login', method='POST', data=login, headers={'Origin': origin})
    session = json.loads(body)
    cookies = list(jar)
    if session.get('tenant_id') != tenant or session.get('scope') != 'admin' or len(session.get('csrf_token', '')) != 43:
        raise Failure('HTTPS authenticated session mismatch')
    if len(cookies) != 1 or cookies[0].name != '__Host-peerloom_admin' or not cookies[0].secure or cookies[0].path != '/':
        raise Failure('HTTPS __Host Secure cookie missing')
    header = headers.get('Set-Cookie', '').lower()
    if 'httponly' not in header or 'samesite=strict' not in header or 'domain=' in header:
        raise Failure('HTTPS cookie policy mismatch')
    call('/admin/api/auth/session')
    old_cookie = cookies[0].name + '=' + cookies[0].value
    call('/admin/api/auth/logout', method='POST', data={}, headers={'Origin': origin}, status=403)
    call('/admin/api/auth/logout', method='POST', data={}, headers={'Origin': origin, 'X-CSRF-Token': session['csrf_token']})
    call('/admin/api/auth/session', headers={'Cookie': old_cookie}, status=401)


def read_exact(stream, count):
    result = bytearray()
    while len(result) < count:
        data = stream.read(count - len(result))
        if not data:
            raise Failure('WSS unexpected EOF')
        result.extend(data)
    return bytes(result)


def send_frame(stream, value):
    payload = json.dumps(value, separators=(',', ':')).encode()
    if len(payload) > 4096:
        raise Failure('WSS fixture output bound')
    mask = os.urandom(4)
    size = bytes([0x80 | len(payload)]) if len(payload) < 126 else b'\xfe' + struct.pack('!H', len(payload))
    stream.write(b'\x81' + size + mask + bytes(value ^ mask[index % 4] for index, value in enumerate(payload)))
    stream.flush()


def receive_frame(stream):
    first, second = read_exact(stream, 2)
    if first != 0x81 or second & 0x80:
        raise Failure('WSS expected one unmasked text frame')
    size = second & 0x7f
    if size == 127:
        raise Failure('WSS 64-bit frame length rejected by fixture')
    if size == 126:
        size = struct.unpack('!H', read_exact(stream, 2))[0]
    if size > 16384:
        raise Failure('WSS input bound')
    return json.loads(read_exact(stream, size))


def verify_default_trust_rejects(port=18443):
    with socket.create_connection(('127.0.0.1', port), timeout=10) as plain:
        try:
            with ssl.create_default_context().wrap_socket(plain, server_hostname='127.0.0.1'):
                raise Failure('synthetic CA unexpectedly trusted without explicit CA file')
        except ssl.SSLCertVerificationError:
            pass


def verify_wss(credential, ca, port=18443):
    if not isinstance(credential, str) or not credential.startswith('dev_') or any(c in credential for c in '\r\n'):
        raise Failure('invalid synthetic device credential')
    context = ssl.create_default_context(cafile=str(ca))
    with socket.create_connection(('127.0.0.1', port), timeout=10) as plain, \
         context.wrap_socket(plain, server_hostname='127.0.0.1') as connection, \
         connection.makefile('rwb') as stream:
        key = base64.b64encode(os.urandom(16)).decode()
        request = (f'GET /v1/device-signal HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n'
                   f'Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n'
                   f'Authorization: Bearer {credential}\r\n\r\n')
        stream.write(request.encode()); stream.flush()
        status = stream.readline(4097)
        if status != b'HTTP/1.1 101 Switching Protocols\r\n':
            raise Failure('authenticated WSS upgrade failed')
        headers, total = {}, len(status)
        while True:
            line = stream.readline(4097); total += len(line)
            if total > 16384 or not line or len(line) > 4096:
                raise Failure('WSS upgrade headers bound')
            if line == b'\r\n':
                break
            name, value = line.decode('ascii').split(':', 1)
            headers[name.lower()] = value.strip()
        expected = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
        if headers.get('sec-websocket-accept') != expected or headers.get('upgrade', '').lower() != 'websocket':
            raise Failure('WSS handshake authentication mismatch')
        hello = {'v': 1, 'type': 'hello', 'id': str(uuid.uuid4()), 'seq': 0,
                 'sent_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'), 'payload': {}}
        send_frame(stream, hello)
        ack = receive_frame(stream)
        if ack.get('type') != 'hello.ack' or ack.get('request_id') != hello['id'] or not ack.get('fencing_token') or ack.get('connection_generation', 0) < 1:
            raise Failure('WSS hello ownership not established')
        beat = dict(hello, type='presence.heartbeat', id=str(uuid.uuid4()), seq=1,
                    connection_generation=ack['connection_generation'], fencing_token=ack['fencing_token'])
        send_frame(stream, beat)
        reply = receive_frame(stream)
        if reply.get('type') != 'presence.ack' or reply.get('request_id') != beat['id'] or reply.get('fencing_token') != ack['fencing_token']:
            raise Failure('WSS authenticated heartbeat failed')


def require_local_docker():
    explicit = os.environ.get('DOCKER_HOST', '')
    if explicit and not explicit.startswith('unix:///'):
        raise Failure('only an explicit local Unix-socket Docker daemon is permitted')
    endpoint = json.loads(invoke(['docker', 'context', 'inspect', '--format', '{{json .Endpoints.docker.Host}}'], capture=True))
    if not isinstance(endpoint, str) or not endpoint.startswith('unix:///') or '\n' in endpoint:
        raise Failure('selected Docker context is not a local Unix socket')


def execute(root=ROOT):
    require_local_docker()
    with socket.socket() as probe:
        try:
            probe.bind(('127.0.0.1', 18443))
        except OSError:
            raise Failure('loopback TLS port in use; existing service will not be stopped') from None
    spec = importlib.util.spec_from_file_location('fixture_secrets', root / 'scripts/generate-dev-secrets.py')
    generator = importlib.util.module_from_spec(spec); spec.loader.exec_module(generator)
    project = 'peerloom-tls-ci-' + uuid.uuid4().hex
    print('本次隔离 TLS Compose 项目: ' + project, flush=True)
    with tempfile.TemporaryDirectory(prefix='peerloom-tls-compose-') as temporary:
        directory = Path(temporary); directory.chmod(0o700)
        generator.generate(directory / '.secrets')
        ca = certificates(directory / 'tls')
        config, image = configuration(root, directory, project)
        path = directory / 'compose.yaml'; path.write_text(yaml.safe_dump(config, sort_keys=False)); path.chmod(0o600)
        environment = dict(os.environ, TLS_CERTIFICATE_FILE=str(directory / 'tls/server.crt'),
                           TLS_PRIVATE_KEY_FILE=str(directory / 'tls/server.key'), TLS_ADMIN_ORIGIN=ORIGIN)
        run = functools.partial(invoke, env=environment)
        # Exercise the actual operator override, not a test-only nginx replacement.
        compose = ['docker', 'compose', '--project-directory', str(root / 'infra'), '-p', project,
                   '-f', str(path), '-f', str(root / 'infra/compose.tls.yaml')]
        built, stage = False, 'configuration'
        try:
            validate_rendered(run(compose + ['config', '--format', 'json'], capture=True))
            stage = 'container build'; run(compose + ['build', 'device-server'], timeout=600); built = True
            stage = 'database startup/migrations'; run(compose + ['up', '-d', '--wait', 'postgres', 'redis'])
            run(compose + ['run', '--rm', '-T', 'migrate'])
            stage = 'isolated synthetic credentials'
            pair = json.loads(run(compose + ['run', '--rm', '-T', '--no-deps', '--entrypoint', 'device-bootstrap', 'device-server', '--development', '--pair'], capture=True))
            bootstrap = json.loads(run(compose + ['run', '--rm', '-T', '--no-deps', '--entrypoint', 'device-bootstrap',
                'migrate', '--development'], capture=True))
            tenant = str(uuid.UUID(bootstrap['tenant_id']))
            password = 'Synthetic TLS gateway ' + secrets.token_urlsafe(32)
            created = json.loads(run(compose + ['run', '--rm', '-T', '--no-deps', '--entrypoint', 'device-admin-user', 'migrate',
                'create', '--offline', '--tenant-id', tenant, '--username', 'gateway_owner', '--scope', 'admin', '--password-stdin'],
                data=(password + '\n').encode(), capture=True))
            if created.get('status') != 'created':
                raise Failure('synthetic admin creation failed')
            stage = 'HTTPS gateway startup'; run(compose + ['up', '-d', '--wait', 'device-server', 'gateway'])
            run(compose + ['exec', '-T', 'gateway', 'nginx', '-t'])
            stage = 'CA/hostname verification and HTTPS management'
            verify_default_trust_rejects()
            run(['curl', '--fail', '--silent', '--show-error', '--noproxy', '*', '--max-time', '10', '--cacert', str(ca), ORIGIN + '/readyz'])
            verify_https(tenant, password, ca)
            stage = 'real authenticated WSS hello/heartbeat'; verify_wss(pair['source']['device_credential'], ca)
        except ToolFailure as error:
            raise Failure('TLS Compose validation failed during ' + stage + '; ' + str(error) + '; secret details withheld') from None
        except Exception:
            raise Failure('TLS Compose validation failed during ' + stage + '; secret details withheld') from None
        finally:
            try:
                run(compose + ['down', '--volumes', '--remove-orphans', '--timeout', '10'], timeout=90)
            finally:
                if built:
                    run(['docker', 'image', 'rm', image], timeout=30)
    print('隔离 HTTPS/WSS：显式 CA+主机名、Secure 管理 Cookie/CSRF/Origin/Host、metrics 拒绝、认证 heartbeat 通过。')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--integration', action='store_true')
    args = parser.parse_args()
    if not args.integration:
        parser.error('requires --integration; never uses an existing deployment')
    os.umask(0o077)
    try:
        execute()
    except Failure as error:
        raise SystemExit(str(error)) from None
    except (OSError, ValueError, KeyError, TypeError):
        raise SystemExit('invalid local fixture input; secret details withheld') from None


if __name__ == '__main__':
    main()
