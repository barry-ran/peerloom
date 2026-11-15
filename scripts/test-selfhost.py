#!/usr/bin/env python3
"""Self-host orchestration regression tests; no Docker or credentials touched."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('selfhost', ROOT / 'deploy/server/selfhost.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
TENANT = '00000000-0000-0000-0000-000000000001'
CREDENTIAL = '00000000-0000-0000-0000-000000000002'
APP = '00000000-0000-0000-0000-000000000003'


class FakeInitializer:
    def __init__(self):
        self.calls = 0

    def generate(self, root):
        self.calls += 1
        (root / '.secrets').mkdir()
        for name in m.SECRET_NAMES:
            (root / '.secrets' / name).write_text('test-only')


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / '.operator').mkdir()
        self.calls = []
        self.init = FakeInitializer()
        self.status = {'tenant_id': TENANT, 'credential_id': CREDENTIAL, 'application_id': APP, 'expired': False,
                       'tenant_active': True, 'scope': 'admin', 'expires_at': 'test-date'}
        self.fail = None
        self.containers = b''
        self.labels = {}
        # Orchestration tests are portable; Linux file safety is covered separately.
        self.patches = [patch.object(m, 'validate_private'),
                        patch.object(m, 'validate_file', side_effect=lambda p, *a: p.read_bytes()),
                        patch.object(m.os, 'geteuid', return_value=1000, create=True),
                        patch.object(m.os, 'getegid', return_value=1000, create=True),
                        patch.object(m, 'create_json', side_effect=self.create)]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)

    def create(self, p, value):
        with p.open('x') as stream:
            json.dump(value, stream)

    def invoke_fake(self, args, **kwargs):
        self.calls.append(args)
        if self.fail and self.fail(args):
            raise RuntimeError('synthetic failure')
        if args[:3] == ['docker', 'ps', '-aq']:
            return self.containers
        if args[:2] == ['docker', 'inspect']:
            return json.dumps(self.labels).encode()
        if 'setup' in args:
            self.create(self.root / '.operator/connection.json', {
                'tenant_id': TENANT, 'application_id': APP, 'credential_id': CREDENTIAL,
                'tenant_name': 'default', 'application_name': 'default',
                'service_credential': 'synthetic-private'})
        if 'setup-verify' in args:
            return json.dumps(self.status).encode()
        return b''

    def up(self):
        return m.up(self.root, 'test-project', 'default', 'default', self.init, self.invoke_fake)

    def test_fresh_and_repeat_never_rotate(self):
        self.up()
        self.up()
        self.assertEqual(self.init.calls, 1)
        self.assertEqual(sum('setup' in c for c in self.calls), 1)
        self.assertFalse(any('issue-key' in c or 'revoke-key' in c for c in self.calls))
        self.assertEqual(self.calls[-1][-5:], ['up', '-d', '--wait', 'device-server', 'gateway'][-6:])

    def test_compose_relative_paths_preserved(self):
        c = m.compose(self.root, 'test')
        self.assertEqual(c[c.index('--project-directory') + 1], str(self.root / 'deploy'))
        self.assertIn(str(self.root / 'deploy/compose.yaml'), c)
        self.assertEqual(c[-1], str(self.root / '.operator/selfhost.compose.json'))

    def test_each_command_failure_retains_reusable_state(self):
        predicates = [lambda a: 'config' in a, lambda a: 'build' in a,
                      lambda a: a[-2:] == ['postgres', 'redis'],
                      lambda a: a[-1:] == ['migrate'], lambda a: 'setup' in a,
                      lambda a: 'setup-verify' in a, lambda a: a[-1:] == ['gateway']]
        for predicate in predicates:
            with self.subTest(predicate=predicate), tempfile.TemporaryDirectory() as raw:
                self.root = Path(raw)
                (self.root / '.operator').mkdir()
                self.init = FakeInitializer()
                self.fail = predicate
                with self.assertRaises(RuntimeError):
                    self.up()
                self.fail = None
                self.up()
                self.assertEqual(self.init.calls, 1)

    def test_reject_foreign_resources_before_secret_creation(self):
        self.containers = b'123456abcdef\n'
        with self.assertRaises(ValueError):
            self.up()
        self.assertEqual(self.init.calls, 0)

    def test_reject_foreign_resource_on_repeat(self):
        self.up()
        self.containers = b'123456abcdef\n'
        self.labels = {'com.docker.compose.project.working_dir': '/another/deploy'}
        with self.assertRaises(ValueError):
            self.up()

    def test_foreign_volume_without_container_rejected(self):
        def run(args, **kwargs):
            if args[:3] == ['docker', 'volume', 'ls']:
                return b'foreign-volume'
            return self.invoke_fake(args, **kwargs)
        with self.assertRaises(ValueError):
            m.up(self.root, 'test-project', 'default', 'default', self.init, run)
        self.assertEqual(self.init.calls, 0)

    def test_reject_existing_secrets_without_owned_state(self):
        (self.root / '.secrets').mkdir()
        with self.assertRaises(ValueError):
            self.up()
        self.assertEqual(self.init.calls, 0)

    def test_reject_changed_settings(self):
        self.up()
        with self.assertRaises(ValueError):
            m.up(self.root, 'different', 'default', 'default', self.init, self.invoke_fake)

    def test_reject_partial_secrets_without_recreating(self):
        self.up()
        (self.root / '.secrets/replay_key').unlink()
        with self.assertRaises(ValueError):
            self.up()
        self.assertEqual(self.init.calls, 1)

    def test_initializer_interruption_requires_manual_review(self):
        def interrupted(root):
            self.init.calls += 1
            (root / '.secrets').mkdir()
            (root / '.secrets/postgres_password').write_text('test-only')
            raise RuntimeError('simulated interruption during secret generation')
        with patch.object(self.init, 'generate', side_effect=interrupted):
            with self.assertRaises(RuntimeError):
                self.up()
        retained = (self.root / '.secrets/postgres_password').read_bytes()
        with self.assertRaises(ValueError):
            self.up()
        self.assertEqual(self.init.calls, 1)
        self.assertEqual((self.root / '.secrets/postgres_password').read_bytes(), retained)
        self.assertFalse(any('setup' in command for command in self.calls))

    def test_expired_revoked_disabled_not_success(self):
        for delta in ({'expired': True}, {'revoked_at': 'test-date'}, {'tenant_active': False}):
            with self.subTest(delta=delta):
                self.up()
                previous = self.status.copy()
                self.status.update(delta)
                with self.assertRaises(ValueError):
                    self.up()
                self.status = previous

    def test_status_filters_secret(self):
        self.up()
        self.status['service_credential'] = 'must-not-print'
        result = m.key_status(self.root, 'test-project', self.invoke_fake)
        self.assertNotIn('service_credential', result)

    def test_status_wrong_identity_rejected(self):
        self.up()
        self.status['tenant_id'] = APP
        with self.assertRaises(ValueError):
            m.key_status(self.root, 'test-project', self.invoke_fake)

    def test_container_write_uses_operator_uid_not_root(self):
        args = m.admin(self.root, 'test', ['setup'])
        self.assertEqual(args[args.index('--user') + 1], '1000:1000')
        self.assertNotIn('--privileged', args)


@unittest.skipUnless(os.name == 'posix', 'Linux file semantics required')
class FileSafetyTests(unittest.TestCase):
    def test_file_modes_links_and_size(self):
        with tempfile.TemporaryDirectory() as raw:
            p = Path(raw) / 'key'
            p.write_bytes(b'test-only')
            p.chmod(0o600)
            self.assertEqual(m.validate_file(p, 0o600), b'test-only')
            p.chmod(0o644)
            with self.assertRaises(ValueError):
                m.validate_file(p, 0o600)
            p.chmod(0o600)
            link = Path(raw) / 'link'
            link.symlink_to(p)
            with self.assertRaises(OSError):
                m.validate_file(link, 0o600)
            link.unlink()
            os.link(p, link)
            with self.assertRaises(ValueError):
                m.validate_file(p, 0o600)

    def test_json_creation_syncs_file_then_parent(self):
        with tempfile.TemporaryDirectory() as raw:
            p = Path(raw) / 'state'
            synced = []
            real_fsync = os.fsync
            def record(fd):
                import stat
                synced.append(stat.S_ISDIR(os.fstat(fd).st_mode))
                real_fsync(fd)
            with patch.object(m.os, 'fsync', side_effect=record):
                m.create_json(p, {'value': 1})
            self.assertEqual(synced, [False, True])

    def test_parent_sync_failure_keeps_file_for_validation(self):
        with tempfile.TemporaryDirectory() as raw:
            p = Path(raw) / 'state'
            real_fsync = os.fsync
            def fail_directory(fd):
                import stat
                if stat.S_ISDIR(os.fstat(fd).st_mode):
                    raise OSError('simulated directory fsync failure')
                real_fsync(fd)
            with patch.object(m.os, 'fsync', side_effect=fail_directory):
                with self.assertRaises(OSError):
                    m.create_json(p, {'value': 1})
            self.assertEqual(m.load_json(p), {'value': 1})
            with self.assertRaises(FileExistsError):
                m.create_json(p, {'value': 2})

    def test_json_creation_is_exclusive(self):
        with tempfile.TemporaryDirectory() as raw:
            p = Path(raw) / 'state'
            m.create_json(p, {'value': 1})
            with self.assertRaises(FileExistsError):
                m.create_json(p, {'value': 2})
            self.assertEqual(m.load_json(p), {'value': 1})


if __name__ == '__main__':
    unittest.main()
