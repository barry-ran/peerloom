#!/usr/bin/env python3
"""实际loopback relay管理回归；会话模式仅旁观已经建立的SDK测试会话。"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import uuid

SPEC = importlib.util.spec_from_file_location('management_test', Path(__file__).with_name('test-management.py'))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def run(args):
    client = MODULE.Client(args.base_url)
    credential = MODULE.read_fixture(args.admin_fixture)
    if args.pair_fixture:
        descriptor = os.open(args.pair_fixture, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(descriptor, 'rb') as stream:
            meta = os.fstat(stream.fileno())
            MODULE.require(stat.S_ISREG(meta.st_mode) and stat.S_IMODE(meta.st_mode) == 0o600,
                           'private regular pair fixture required')
            if hasattr(os, 'getuid'):
                MODULE.require(meta.st_uid == os.getuid(), 'pair fixture must belong to current user')
            data = stream.read(65537)
        MODULE.require(len(data) <= 65536, 'pair fixture too large')
        pair = json.loads(data)
        target = pair['target']
        device = str(uuid.UUID(target['device_id']))
        token = target['device_credential']
        MODULE.require(re.fullmatch(r'dev_[A-Za-z0-9_-]{43}', token), 'invalid device fixture')
        # psql uses already-configured local test PG* environment, never a URL argv.
        MODULE.require(os.environ.get('PGHOST') == '127.0.0.1', 'local test database required')
        query = "SELECT id::text FROM sessions WHERE target_device_id='" + device + "' AND state IN('connecting','connected') ORDER BY created_at DESC LIMIT 1"
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            result = subprocess.run(['psql', '-X', '-A', '-t', '-q', '-c', query],
                                    capture_output=True, text=True, timeout=3, check=True)
            session = result.stdout.strip()
            if session:
                session = str(uuid.UUID(session))
                break
            time.sleep(.1)
        else:
            raise MODULE.CheckFailure('SDK did not establish accepted session in deadline')
        route = '/v1/device-sessions/' + session + '/ice-servers'
        first = client.request('GET', route, 200, token)
        second = client.request('GET', route, 200, token)
        MODULE.require(first == second and len(first['ice_servers']) == 1,
                       'actual ICE endpoint reuse mismatch: keys=' + str([key for key in first if first[key] != second.get(key)]) + ', credential_fields=' + str([key for key in first.get('ice_servers',[{}])[0] if first['ice_servers'][0][key] != second.get('ice_servers',[{}])[0].get(key)]))
        value = first['ice_servers'][0]
        MODULE.require(value['urls'] == ['turn:relay.example.com:3478?transport=udp']
                       and value['username'] and value['credential'], 'actual ICE response shape mismatch')
        client.request('GET', route, 401, credential)
        print('PASS: actual accepted SDK session ICE HTTP issuance/reuse and audience isolation; SDK transport still DirectOnly')
        return
    create = {'name': 'local-approved-relay', 'endpoint': 'turn:relay.example.com:3478?transport=udp',
              'secret_ref': 'test-tenant-v1'}
    node = client.request('POST', '/v1/relay-nodes', 201, credential, create, 'relay-live-create')
    replay = client.request('POST', '/v1/relay-nodes', 201, credential, create, 'relay-live-create')
    MODULE.require(node == replay, 'node creation replay changed')
    route = '/v1/relay-nodes/' + node['id']
    client.request('PATCH', route, 422, credential, {'enabled': None}, 'reject-null-enabled')
    client.request('POST', '/v1/relay-nodes', 422, credential,
                   dict(create, endpoint='turn:unapproved.example.com:3478?transport=udp'), 'reject-url')
    changed = client.request('PATCH', route, 200, credential, {'region': 'local'}, 'relay-live-region')
    MODULE.require(changed['revision'] == node['revision'] + 1, 'node revision did not advance')
    page = client.request('GET', '/v1/relay-nodes?limit=1', 200, credential)
    MODULE.require(len(page['items']) == 1, 'relay list missing node')
    removed = client.request('DELETE', route, 200, credential, key='relay-live-disable')
    MODULE.require(removed['enabled'] is False, 'node soft delete failed')
    client.request('PATCH', route, 200, credential, {'enabled': True}, 'relay-live-enable')
    print('PASS: actual relay HTTP typed CRUD, approved URL, revision, idempotency and pagination')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', required=True)
    parser.add_argument('--admin-fixture', required=True)
    parser.add_argument('--pair-fixture')
    args = parser.parse_args()
    try:
        run(args)
    except MODULE.CheckFailure as error:
        print('Relay HTTP regression failed:', error)
        return 1
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print('Relay HTTP regression failed: fixture, local service or database unavailable')
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
