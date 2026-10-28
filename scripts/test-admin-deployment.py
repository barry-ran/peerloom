#!/usr/bin/env python3
"""管理员部署静态结构测试；不冒充真实 Docker/代理/浏览器验证。"""
from pathlib import Path
import re
import subprocess
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]


class AdminDeploymentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compose = yaml.safe_load((ROOT / 'infra/compose.yaml').read_text())
        cls.nginx = (ROOT / 'infra/gateway/nginx.conf').read_text()

    def test_admin_disabled_by_default_and_only_server_gets_switches(self):
        services = self.compose['services']
        self.assertEqual(services['device-server']['environment']['ADMIN_ORIGIN'], '${ADMIN_ORIGIN:-}')
        self.assertEqual(services['device-server']['environment']['ADMIN_DEVELOPMENT_LOOPBACK'], '${ADMIN_DEVELOPMENT_LOOPBACK:-}')
        for name, value in services.items():
            if name != 'device-server':
                self.assertNotIn('ADMIN_ORIGIN', value.get('environment', {}))
                self.assertNotIn('ADMIN_DEVELOPMENT_LOOPBACK', value.get('environment', {}))

    def test_database_cache_and_gateway_remain_isolated(self):
        services = self.compose['services']
        self.assertFalse(services['postgres'].get('ports'))
        self.assertFalse(services['redis'].get('ports'))
        self.assertEqual(services['gateway']['ports'], ['127.0.0.1:18080:8080'])
        self.assertTrue(self.compose['networks']['backend']['internal'])
        for name in ('device-server', 'gateway', 'migrate'):
            self.assertTrue(services[name]['read_only'])
            self.assertEqual(services[name]['cap_drop'], ['ALL'])
        self.assertEqual(services['migrate']['secrets'], ['database_url'])

    def test_proxy_preserves_origin_port_and_does_not_trust_forwarded_chain(self):
        self.assertIn('location /admin/ {', self.nginx)
        self.assertIn('location = /v1/device-signal {', self.nginx)
        self.assertNotIn('proxy_set_header Host $host;', self.nginx)
        self.assertEqual(self.nginx.count('proxy_pass http://device-server:8080;'), 3)
        self.assertEqual(self.nginx.count('proxy_set_header Host $http_host;'), 3)
        self.assertEqual(self.nginx.count('proxy_set_header X-Forwarded-For $remote_addr;'), 3)
        self.assertNotIn('$proxy_add_x_forwarded_for', self.nginx)
        self.assertNotIn('$http_x_forwarded_for', self.nginx)
        self.assertRegex(self.nginx, r'location = /metrics\s*\{\s*return 404;\s*\}')

    def test_container_builds_cli_without_running_account_creation(self):
        dockerfile = (ROOT / 'infra/Dockerfile').read_text()
        self.assertIn('go build -trimpath -o /out/device-admin-user ./cmd/device-admin-user', dockerfile)
        self.assertIn('COPY --from=build /out/ /usr/local/bin/', dockerfile)
        self.assertIn('USER 65532:65532', dockerfile)
        self.assertIn('ENTRYPOINT ["device-server"]', dockerfile)
        self.assertNotRegex(dockerfile, r'(?im)^RUN .*device-admin-user (create|change)')
        self.assertNotRegex(dockerfile, r'(?im)^FROM node:')

    def test_cross_platform_artifact_loop_includes_admin_user(self):
        script = ROOT / 'scripts/build.sh'
        body = script.read_text()
        self.assertRegex(body, r'for binary in [^;]*\bdevice-admin-user; do')
        self.assertIn('linux/amd64 linux/arm64 darwin/arm64 windows/amd64', body)
        self.assertIn('"$root/dist/$os-$arch/$binary$suffix"', body)
        subprocess.run(['bash', '-n', str(script)], check=True)
        self.assertLess(body.index('package-third-party.py'), body.index('cp -R \"$root/third_party/admin-web-build/.\"'))
        self.assertIn('admin-web-build/package-lock.json', body)


if __name__ == '__main__':
    unittest.main()
