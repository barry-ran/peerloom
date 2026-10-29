#!/usr/bin/env python3
"""Offline contract tests for the intentionally small GitHub path-filter subset.

This checks configuration and mixed-change semantics, not a claim of executing
GitHub's event engine. No credentials, remote dispatch, or repository mutations.
"""
from pathlib import Path
import re
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]
FILES = ('ci.yml', 'native.yml', 'android.yml', 'admin-web.yml')
IGNORED = ['README.md', 'docs/*.md', 'docs/assets/peerloom-banner.svg',
           'deploy/server/README.md', 'bindings/android/README.md',
           'bindings/android/scripts/Maven证据说明.md', 'bindings/ios/Apple封装说明.md',
           'release/approved-plan.json',
           'scripts/release-admin.py', 'scripts/release-policy.py',
           'scripts/test-release-admin.py', 'scripts/test-workflow-triggers.py',
           '.github/workflows/release-admin.yml']


def matches(pattern, path):
    # Fixed branch '**' spans slashes; path '*' excludes slashes.
    expression = re.escape(pattern).replace(r'\*\*', '\x00').replace(r'\*', '[^/]*').replace('\x00', '.*')
    return re.fullmatch(expression, path) is not None


def would_run(config, event, branch, changed):
    if event not in config:
        return False
    if event == 'workflow_dispatch':
        return True
    options = config[event] or {}
    if 'branches' in options and not any(matches(pattern, branch) for pattern in options['branches']):
        return False
    if event == 'push' and branch in options.get('branches-ignore', []):
        return False
    if 'paths' in options:
        return any(any(matches(pattern,name) for pattern in options['paths']) for name in changed)
    return any(not any(matches(pattern, name) for pattern in options.get('paths-ignore', []))
               for name in changed)


class Triggers(unittest.TestCase):
    def setUp(self):
        self.workflows = {name: yaml.load((ROOT/'.github/workflows'/name).read_text(encoding='utf-8'),
                                        Loader=yaml.BaseLoader) for name in FILES}

    def test_exact_filters_and_read_only_permissions(self):
        for name, workflow in self.workflows.items():
            with self.subTest(name=name):
                on=workflow['on']
                self.assertEqual(set(on), {'push','workflow_dispatch','pull_request'} if name in ('ci.yml','admin-web.yml') else {'push','workflow_dispatch'})
                self.assertEqual(on['push'], {'branches-ignore':['master'],'paths-ignore':IGNORED})
                if 'pull_request' in on:
                    self.assertEqual(on['pull_request'], {'paths-ignore':IGNORED})
                self.assertEqual(workflow['permissions'], {'contents':'read'})
                self.assertNotIn('pull_request_target',on)

    def test_documentation_and_publication_only_are_not_functional_runs(self):
        for workflow in self.workflows.values():
            for changed in (['README.md'], ['docs/部署指南.md'], ['docs/assets/peerloom-banner.svg'],
                            ['release/approved-plan.json'], ['README.md','release/approved-plan.json'],
                            ['deploy/server/README.md','bindings/android/README.md']):
                self.assertFalse(would_run(workflow['on'],'push','feat/validation-release-packaging',changed))
                if 'pull_request' in workflow['on']:
                    self.assertFalse(would_run(workflow['on'],'pull_request','master',changed))

    def test_functional_and_mixed_changes_always_validate_off_master(self):
        paths=['src/device-sdk/device-core/src/sdk.rs','src/device-server/go.mod','src/device-sdk/Cargo.lock',
               'scripts/build.sh','.github/workflows/native.yml','deploy/server/init-private.py',
               'infra/migrations/000010_future.up.sql','api/openapi.json','AGENTS.md',
               'release/maven-license-gaps.json','third_party/license-evidence/README.md',
               'docs/program.py','docs/assets/other.svg','docs/subfolder/code.md']
        for workflow in self.workflows.values():
            for branch in ('feat/change','fix/change','validation/change'):
                for path in paths:
                    self.assertTrue(would_run(workflow['on'],'push',branch,['README.md',path]),path)
                    if 'pull_request' in workflow['on']:
                        self.assertTrue(would_run(workflow['on'],'pull_request','master',['README.md',path]),path)

    def test_master_fast_forward_does_not_repeat_validated_functional_runs(self):
        for workflow in self.workflows.values():
            self.assertFalse(would_run(workflow['on'],'push','master',['src/device-server/cmd/device-server/main.go']))

    def test_explicit_dispatch_preserves_full_validation(self):
        for workflow in self.workflows.values():
            for branch in ('master','feat/validation-release-packaging'):
                self.assertTrue(would_run(workflow['on'],'workflow_dispatch',branch,[]))

    def test_publication_workflow_exact_trigger_paths_and_branches(self):
        release=yaml.load((ROOT/'.github/workflows/release-admin.yml').read_text(encoding='utf-8'),Loader=yaml.BaseLoader)
        paths=['release/approved-plan.json','scripts/release-admin.py','scripts/release-policy.py',
               'scripts/test-release-admin.py','scripts/test-workflow-triggers.py',
               '.github/workflows/release-admin.yml','.github/workflows/ci.yml',
               '.github/workflows/native.yml','.github/workflows/android.yml','.github/workflows/admin-web.yml']
        self.assertEqual(release['on'],{'push':{'branches':['master','feat/**'],'paths':paths}})
        for branch in ('master','feat/capacity-unlimited','feat/release/v0.1.3'):
            for changed in (['README.md'],['docs/部署指南.md'],['README.md','docs/assets/peerloom-banner.svg'],
                            ['README.md','src/device-sdk/device-core/src/sdk.rs']):
                self.assertFalse(would_run(release['on'],'push',branch,changed))
            self.assertTrue(would_run(release['on'],'push',branch,['release/approved-plan.json']))
            for path in paths:
                self.assertTrue(would_run(release['on'],'push',branch,['README.md',path]))
        for event,branch in (('push','feature/unrelated'),('push','fix/release'),('push','feat'),('pull_request','master'),('workflow_dispatch','master')):
            self.assertFalse(would_run(release['on'],event,branch,['release/approved-plan.json']))
        for workflow in self.workflows.values():
            self.assertFalse(would_run(workflow['on'],'push','feat/validation-release-packaging',['release/approved-plan.json']))
            self.assertTrue(would_run(workflow['on'],'push','feat/validation-release-packaging',['README.md','src/device-sdk/device-core/src/sdk.rs']))

    def test_candidate_read_gate_and_master_only_write_gate(self):
        release=yaml.load((ROOT/'.github/workflows/release-admin.yml').read_text(encoding='utf-8'),Loader=yaml.BaseLoader)
        self.assertEqual(release['jobs']['preflight']['if'],
            "github.repository == 'barry-ran/peerloom' && github.event_name == 'push' && (github.ref == 'refs/heads/master' || (startsWith(github.ref, 'refs/heads/feat/') && github.ref != 'refs/heads/feat/'))")
        self.assertEqual(release['jobs']['apply-approved-plan']['if'],
            "needs.preflight.outputs.enabled == 'true' && github.repository == 'barry-ran/peerloom' && github.ref == 'refs/heads/master'")
        self.assertEqual(release['permissions'], {'contents':'read','actions':'read'})
        self.assertNotIn('permissions', release['jobs']['preflight'])
        # An empty wildcard suffix may match the trigger pattern, but cannot enter preflight.
        self.assertTrue(would_run(release['on'],'push','feat/',['release/approved-plan.json']))
        self.assertNotIn('workflow_dispatch', release['on'])

    def test_publication_code_only_is_short_but_mixed_product_changes_are_full(self):
        publication = ['scripts/release-admin.py', 'scripts/release-policy.py',
                       'scripts/test-release-admin.py', 'scripts/test-workflow-triggers.py',
                       '.github/workflows/release-admin.yml']
        product = ['src/device-sdk/device-core/src/sdk.rs', 'src/device-server/go.mod',
                   'scripts/test-capacity.py', 'scripts/test-capacity-ci.py',
                   'scripts/test-package-release.py', 'scripts/build.sh',
                   'scripts/release-policy.py.extra', '.github/workflows/other.yml',
                   *('.github/workflows/' + name for name in FILES)]
        release=yaml.load((ROOT/'.github/workflows/release-admin.yml').read_text(encoding='utf-8'),Loader=yaml.BaseLoader)
        for branch in ('feat/capacity-unlimited', 'feat/release/v0.1.3'):
            for path in publication:
                self.assertTrue(would_run(release['on'], 'push', branch, ['README.md', path]))
                for workflow in self.workflows.values():
                    self.assertFalse(would_run(workflow['on'], 'push', branch, ['README.md', path]))
                    if 'pull_request' in workflow['on']:
                        self.assertFalse(would_run(workflow['on'], 'pull_request', 'master', [path]))
                    for code in product:
                        self.assertTrue(would_run(workflow['on'], 'push', branch, [path, code]), code)
                        if 'pull_request' in workflow['on']:
                            self.assertTrue(would_run(workflow['on'], 'pull_request', 'master', [path, code]), code)
        # This transition edits functional workflows themselves: it is not a skip.
        for workflow in self.workflows.values():
            for name in FILES:
                self.assertTrue(would_run(workflow['on'], 'push', 'feat/capacity-unlimited',
                                         publication + ['.github/workflows/' + name]))

    def test_canonical_job_names_are_preserved(self):
        self.assertEqual(set(self.workflows['ci.yml']['jobs']), {'verify', 'capacity-500'})
        self.assertEqual(set(self.workflows['native.yml']['jobs']), {'windows-native','apple-native'})
        self.assertEqual(self.workflows['admin-web.yml']['jobs']['admin-browser-required']['name'], 'PostgreSQL + Chromium 管理安全门禁')
        self.assertEqual(self.workflows['android.yml']['jobs']['build']['name'], 'android-build')


if __name__ == '__main__':
    unittest.main()
