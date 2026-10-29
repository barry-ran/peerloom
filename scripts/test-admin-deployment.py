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

    def test_server_artifact_is_linux_amd64_with_all_operator_tools(self):
        script = ROOT / 'scripts/build.sh'
        body = script.read_text()
        self.assertRegex(body, r'for binary in [^;]*\bdevice-admin-user; do')
        self.assert_server_sdk_split(body, (ROOT / 'scripts/package-release.py').read_text(encoding='utf-8'))
        self.assertIn('"$root/dist/$os-$arch/$binary$suffix"', body)
        subprocess.run(['bash', '-n', str(script)], check=True)
        self.assert_build_notice_pipeline(body, (ROOT / 'scripts/package-third-party.py').read_text())

    def assert_server_sdk_split(self, body, package):
        import re
        targets = re.findall(r'for target in ([^;]+); do', body)
        self.assertEqual(targets, ['linux/amd64'])
        binaries = re.findall(r'for binary in ([^;]+); do', body)
        self.assertEqual(binaries, ['device-server device-migrate device-bootstrap device-admin device-admin-user'])
        self.assertIn('CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build', body)
        for platform in ('linux-x86_64', 'server-linux-amd64'):
            self.assertIn(f'python3 "$root/scripts/package-release.py" --platform {platform} --output "$root/dist/release/{platform}"', body.splitlines())
        self.assertIn("sources = [(root / 'dist/c-abi-linux-x86_64', 'sdk')]", package)
        self.assertIn("elif args.platform == 'server-linux-amd64':\n        sources = server_sources(root)", package)
        self.assertNotIn('go-crossbuilds', package)

    def test_server_sdk_split_rejects_old_targets_missing_tools_or_mixed_payload(self):
        body = (ROOT/'scripts/build.sh').read_text(encoding='utf-8')
        package = (ROOT/'scripts/package-release.py').read_text(encoding='utf-8')
        cases = [
            (body.replace('for target in linux/amd64;', 'for target in linux/amd64 linux/arm64;'), package),
            (body.replace(' device-admin-user;', ';'), package),
            (body.replace('--platform server-linux-amd64', '--platform linux-x86_64'), package),
            (body, package.replace("'sdk')]", "'go-crossbuilds')]")),
        ]
        for changed_body, changed_package in cases:
            with self.subTest(body_changed=changed_body != body):
                with self.assertRaises(AssertionError):
                    self.assert_server_sdk_split(changed_body, changed_package)

    def assert_build_notice_pipeline(self, body, producer):
        invocation = 'python3 "$root/scripts/package-third-party.py" --include-build-notices'
        self.assertIn(invocation, body.splitlines())
        self.assertLess(body.index(invocation), body.index('python3 "$root/scripts/package-release.py"'))
        self.assertIn("sources['admin-web-build/package-lock.json'] = root / 'src/admin-web/package-lock.json'", producer)
        self.assertIn("admin = root / 'third_party/admin-web-build'", producer)
        self.assertIn('if args.include_build_notices:\n        copy_build_notices(root, output)', producer)
        self.assertIn('append_owned_manifest(output, owned)', producer)
        self.assertIn('if actual != set(expected):', producer)
        self.assertIn('if sha_file(output / name) != checksum:', producer)

    def test_build_notice_pipeline_rejects_missing_flag_or_wrong_producer(self):
        body = (ROOT / 'scripts/build.sh').read_text()
        producer = (ROOT / 'scripts/package-third-party.py').read_text()
        cases = [
            (body.replace(' --include-build-notices', ''), producer),
            (body.replace('scripts/package-third-party.py', 'scripts/generate-third-party.py'), producer),
            (body, producer.replace('append_owned_manifest(output, owned)', 'print("not checksummed")')),
            (body, producer.replace('if actual != set(expected):', 'if False:')),
        ]
        for changed_body, changed_producer in cases:
            with self.subTest(body_changed=changed_body != body, producer_changed=changed_producer != producer):
                with self.assertRaises(AssertionError):
                    self.assert_build_notice_pipeline(changed_body, changed_producer)



if __name__ == '__main__':
    unittest.main()
