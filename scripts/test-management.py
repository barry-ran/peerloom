#!/usr/bin/env python3
"""真实 loopback 管理 HTTP 回归；输入/输出秘密文件必须仅供当前用户访问。"""
import argparse
from datetime import datetime, timedelta, timezone
import http.client
import ipaddress
import json
import os
import re
import stat
import sys
import urllib.parse
import uuid

MAX_RESPONSE = 1 << 20


class CheckFailure(Exception):
    """Only nonsecret diagnostic labels belong in this exception."""


def require(condition, label):
    if not condition:
        raise CheckFailure(label)


def read_fixture(path):
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        require(stat.S_ISREG(metadata.st_mode), 'fixture must be a regular file')
        require(stat.S_IMODE(metadata.st_mode) == 0o600, 'fixture requires mode 0600')
        if hasattr(os, 'getuid'):
            require(metadata.st_uid == os.getuid(), 'fixture must belong to current user')
        data = stream.read(65537)
    require(len(data) <= 65536, 'fixture exceeds size bound')
    value = json.loads(data)
    require(isinstance(value, dict), 'fixture must be an object')
    secret = value.get('service_credential')
    require(isinstance(secret, str) and re.fullmatch(r'svc_[A-Za-z0-9_-]{43}', secret),
            'fixture requires tenant service credential')
    return secret


class Client:
    def __init__(self, base_url):
        parsed = urllib.parse.urlsplit(base_url)
        require(parsed.scheme in ('http', 'https') and parsed.username is None
                and parsed.password is None and not parsed.query and not parsed.fragment
                and parsed.path in ('', '/'), 'base URL must be a plain loopback origin')
        try:
            address = ipaddress.ip_address(parsed.hostname or '')
        except ValueError:
            raise CheckFailure('base URL requires a numeric loopback address') from None
        require(address.is_loopback, 'non-loopback base URL refused')
        self.host = str(address)
        self.port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        self.connection_type = http.client.HTTPSConnection if parsed.scheme == 'https' else http.client.HTTPConnection
        self.requests = 0

    def request(self, method, path, expected, credential=None, body=None, key=None):
        require(path.startswith('/v1/') and not path.startswith('//'), 'invalid test endpoint')
        connection = self.connection_type(self.host, self.port, timeout=10)
        headers = {'Accept': 'application/json'}
        if credential:
            headers['Authorization'] = 'Bearer ' + credential
        if key:
            headers['Idempotency-Key'] = key
        payload = None
        if body is not None:
            payload = json.dumps(body, ensure_ascii=False, separators=(',', ':')).encode()
            headers['Content-Type'] = 'application/json'
        try:
            # http.client neither follows redirects nor consults proxy environment.
            connection.request(method, path, body=payload, headers=headers)
            response = connection.getresponse()
            route = re.sub(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', '{id}', path.split('?')[0])
            require(response.status == expected, f'{method} {route} expected status {expected}, got {response.status}')
            length = response.getheader('Content-Length')
            if length is not None:
                require(int(length) <= MAX_RESPONSE, 'HTTP response exceeds size bound')
            raw = response.read(MAX_RESPONSE + 1)
            require(len(raw) <= MAX_RESPONSE, 'HTTP response exceeds size bound')
            value = json.loads(raw)
            require(isinstance(value, dict), 'HTTP response must be an object')
            self.requests += 1
            return value
        finally:
            connection.close()


def write_pair(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(value, stream, ensure_ascii=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        os.unlink(path)
        raise


def exercise(client, admin, foreign=None, reader=None):
    run_id = uuid.uuid4().hex
    key = lambda name: run_id + '-' + name
    call = client.request
    apps = []
    for index in range(2):
        body = {'name': 'HTTP回归-' + str(index), 'require_target_approval': True}
        application = call('POST', '/v1/applications', 201, admin, body, key('app-' + str(index)))
        repeat = call('POST', '/v1/applications', 201, admin, body, key('app-' + str(index)))
        require(application['id'] == repeat['id'], 'application replay created a duplicate')
        apps.append(application['id'])
    call('POST', '/v1/applications', 409, admin, {'name': 'different'}, key('app-0'))
    if reader:
        call('GET', '/v1/applications', 200, reader)
        call('POST', '/v1/applications', 403, reader, {'name': 'denied'}, key('read-denied'))
    if foreign:
        call('GET', '/v1/applications/' + apps[0], 404, foreign)

    def register(application, label):
        body = {'application_id': application, 'expires_in_seconds': 300}
        grant = call('POST', '/v1/registration-grants', 201, admin, body, key('reg-' + label))
        replay = call('POST', '/v1/registration-grants', 201, admin, body, key('reg-' + label))
        require(grant['grant'] == replay['grant'], 'registration grant replay changed secret')
        registration = {'application_id': application, 'platform': 'linux',
                        'installation_public_key': 'http-public-label-' + uuid.uuid4().hex,
                        'registration_grant': grant['grant']}
        device = call('POST', '/v1/device-registrations', 201, body=registration, key=key('device-' + label))
        return {'application_id': application, **device}

    sacrificial = [register(apps[i], 'sacrificial-' + str(i)) for i in range(2)]
    source, target = sacrificial
    call('GET', '/v1/device-self', 401, admin)
    call('GET', '/v1/applications', 401, source['device_credential'])
    call('GET', '/v1/device-self', 200, source['device_credential'])
    device_path = '/v1/devices/' + source['device_id']
    patched = call('PATCH', device_path, 200, admin, {'max_connections': 0}, key('patch-zero'))
    require(patched['max_connections'] == 0 and patched['connectable'] is True, 'PATCH lost zero or changed omitted bool')
    patched = call('PATCH', device_path, 200, admin,
                   {'max_connections': None, 'connectable': False, 'tags': {'role': run_id}}, key('patch-null'))
    require(patched['max_connections'] is None and patched['connectable'] is False, 'PATCH lost null inheritance or false')
    call('PATCH', device_path, 422, admin, {}, key('empty-patch'))
    call('PATCH', device_path, 422, admin, {'tenant_id': str(uuid.uuid4())}, key('unknown-patch'))
    tags = urllib.parse.urlencode({'tags': json.dumps({'role': run_id}), 'limit': '1'})
    filtered = call('GET', '/v1/devices?' + tags, 200, admin)
    require(len(filtered['items']) == 1 and filtered['items'][0]['id'] == source['device_id'], 'tag filter mismatch')
    by_app = call('GET', '/v1/devices?' + urllib.parse.urlencode({'application_id': apps[0]}), 200, admin)
    require(all(item['application_id'] == apps[0] for item in by_app['items']), 'application filter leaked devices')
    call('GET', '/v1/devices?online=false&limit=1', 200, admin)
    changed = call('PATCH', '/v1/applications/' + apps[0], 200, admin,
                   {'name': 'HTTP重命名'}, key('application-patch'))
    require(changed['application']['enabled'] and changed['application']['require_target_approval'], 'application PATCH changed omitted bools')
    if foreign:
        call('GET', device_path, 404, foreign)
        call('POST', device_path + '/revoke', 404, foreign, key=key('foreign-device-revoke'))

    expires = (datetime.now(timezone.utc) + timedelta(minutes=20)).replace(microsecond=0)
    grant_body = {'source_device_id': source['device_id'], 'target_device_id': target['device_id'],
                  'expires_at': expires.isoformat().replace('+00:00', 'Z'), 'expiry_action': 'terminate', 'max_sessions': 1}
    grant = call('POST', '/v1/connection-grants', 201, admin, grant_body, key('connection-grant'))
    equivalent = dict(grant_body, expires_at=expires.astimezone(timezone(timedelta(hours=8))).isoformat())
    replay = call('POST', '/v1/connection-grants', 201, admin, equivalent, key('connection-grant'))
    require(grant['id'] == replay['id'] and grant['expires_at'] == replay['expires_at'], 'expiry replay changed issuance')
    call('POST', '/v1/connection-grants', 422, admin,
         dict(grant_body, expires_in_seconds=0), key('both-expiry'))
    call('POST', '/v1/connection-grants', 422, admin,
         dict(grant_body, expires_at='2000-01-01T00:00:00Z'), key('expired-grant'))
    if foreign:
        call('POST', '/v1/connection-grants', 404, foreign, grant_body, key('foreign-grant'))
        call('DELETE', '/v1/connection-grants/' + grant['id'], 404, foreign, key=key('foreign-delete'))
    call('DELETE', '/v1/connection-grants/' + str(uuid.uuid4()), 404, admin, key=key('missing-delete'))
    revoked = call('DELETE', '/v1/connection-grants/' + grant['id'], 200, admin, key=key('grant-revoke'))
    require(revoked['revoked'] is True, 'grant was not revoked')
    read_grant = call('GET', '/v1/connection-grants/' + grant['id'], 200, admin)
    require(read_grant['revoked_at'] is not None, 'grant revoke not persisted')
    call('POST', device_path + '/revoke', 200, admin, key=key('device-revoke'))
    call('GET', '/v1/device-self', 401, source['device_credential'])
    for route in ('applications', 'devices', 'connection-grants', 'sessions', 'audit-events'):
        page = call('GET', '/v1/' + route + '?limit=1', 200, admin)
        require(isinstance(page.get('items'), list) and len(page['items']) <= 1, 'list shape or page bound mismatch')
        if page.get('next_cursor'):
            call('GET', '/v1/' + route + '?' + urllib.parse.urlencode({'limit': 1, 'cursor': page['next_cursor']}), 200, admin)
    require(call('GET', '/v1/audit-events?limit=1', 200, admin)['items'], 'audit log is empty')

    # Fresh final identities have never been revoked or rotated. Only these are
    # exported for the real Rust WSS/authorization/WebRTC facade regression.
    pair = {name: register(apps[index], 'fresh-' + name) for index, name in enumerate(('source', 'target'))}
    final_grant = {'source_device_id': pair['source']['device_id'], 'target_device_id': pair['target']['device_id'],
                   'expires_at': (datetime.now(timezone.utc) + timedelta(minutes=20)).isoformat(),
                   'expiry_action': 'terminate', 'max_sessions': 1}
    call('POST', '/v1/connection-grants', 201, admin, final_grant, key('fresh-pair-grant'))
    return pair


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', required=True)
    parser.add_argument('--admin-fixture', required=True)
    parser.add_argument('--foreign-admin-fixture')
    parser.add_argument('--read-fixture')
    parser.add_argument('--pair-output', help='new 0600 JSON file; refuses overwrite')
    args = parser.parse_args()
    try:
        client = Client(args.base_url)
        admin = read_fixture(args.admin_fixture)
        foreign = read_fixture(args.foreign_admin_fixture) if args.foreign_admin_fixture else None
        reader = read_fixture(args.read_fixture) if args.read_fixture else None
        if args.pair_output:
            require(not os.path.lexists(args.pair_output), 'pair output already exists')
        pair = exercise(client, admin, foreign, reader)
        if args.pair_output:
            write_pair(args.pair_output, pair)
        print(f'管理 HTTP 回归通过：{client.requests} 个真实请求；跨租户测试={foreign is not None}；只读权限测试={reader is not None}。')
        return 0
    except CheckFailure as error:
        print('管理 HTTP 回归失败：' + str(error), file=sys.stderr)
    except Exception:
        # Never dump transport bodies, URLs, argv, JSON, credentials or traceback.
        print('管理 HTTP 回归失败：本地文件、网络或响应解析错误（秘密已隐藏）。', file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())
