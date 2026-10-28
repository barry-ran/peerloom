#!/usr/bin/env python3
"""只在显式 loopback 隔离测试中，经真实管理 HTTP 创建新的生命周期测试身份。"""
import argparse
import importlib.util
import os
from pathlib import Path
import sys
import uuid

spec = importlib.util.spec_from_file_location('management_fixture', Path(__file__).with_name('test-management.py'))
management = importlib.util.module_from_spec(spec)
spec.loader.exec_module(management)


def prepare(base_url, admin_fixture, output, direct_reset=False):
    management.require(not os.path.lexists(output), 'pair output already exists')
    client = management.Client(base_url)
    admin = management.read_fixture(admin_fixture)
    pair = management.exercise(client, admin)
    if direct_reset:
        application = str(uuid.UUID(pair['source']['application_id']))
        result = client.request('PATCH', '/v1/applications/' + application, 200, admin,
                                {'registration_mode': 'direct'}, 'ci-direct-' + uuid.uuid4().hex)
        management.require(result.get('application', {}).get('registration_mode') == 'direct',
                           'direct registration mode was not persisted')
        pair['direct_reset_enabled'] = True
    management.write_pair(output, pair)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', required=True)
    parser.add_argument('--admin-fixture', required=True)
    parser.add_argument('--pair-output', required=True)
    parser.add_argument('--direct-reset', action='store_true')
    args = parser.parse_args()
    try:
        prepare(args.base_url, args.admin_fixture, args.pair_output, args.direct_reset)
        print('生命周期隔离 fixture 已通过管理 HTTP 创建；秘密仅写入新建 0600 文件。')
        return 0
    except Exception:
        print('生命周期 fixture 失败；文件、网络与响应细节已隐藏。', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
