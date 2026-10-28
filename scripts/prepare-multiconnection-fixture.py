#!/usr/bin/env python3
"""仅隔离 loopback CI：真实管理 HTTP 创建三设备；秘密仅新建0600文件。"""
import argparse
from datetime import datetime, timedelta, timezone
import importlib.util
import os
from pathlib import Path
import sys
import uuid

spec = importlib.util.spec_from_file_location('management_fixture', Path(__file__).with_name('test-management.py'))
management = importlib.util.module_from_spec(spec)
spec.loader.exec_module(management)


def prepare(base_url, admin_fixture, output):
    management.require(not os.path.lexists(output), 'output already exists')
    client = management.Client(base_url)
    admin = management.read_fixture(admin_fixture)
    pair = management.exercise(client, admin)
    application = str(uuid.UUID(pair['target']['application_id']))
    key = 'multi-' + uuid.uuid4().hex
    grant = client.request('POST', '/v1/registration-grants', 201, admin,
                           {'application_id': application, 'expires_in_seconds': 300}, key + '-grant')
    third = client.request('POST', '/v1/device-registrations', 201, body={
        'application_id': application, 'platform': 'linux',
        'installation_public_key': key, 'registration_grant': grant['grant'],
    }, key=key + '-register')
    pair['third'] = {'application_id': application, **third}
    client.request('POST', '/v1/connection-grants', 201, admin, {
        'source_device_id': pair['source']['device_id'], 'target_device_id': third['device_id'],
        'expires_at': (datetime.now(timezone.utc) + timedelta(minutes=20)).isoformat(),
        'expiry_action': 'terminate', 'max_sessions': 1,
    }, key + '-connect')
    management.write_pair(output, pair)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', required=True)
    parser.add_argument('--admin-fixture', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    try:
        prepare(args.base_url, args.admin_fixture, args.output)
        print('三设备隔离 fixture 已创建；秘密仅存于新0600文件。')
        return 0
    except Exception:
        print('三设备 fixture 创建失败；响应与秘密不输出。', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
