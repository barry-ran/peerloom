#!/usr/bin/env python3
"""无外部服务的本地备份工具安全/编排回归。"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
import uuid
from urllib.parse import quote
from unittest import mock

spec = importlib.util.spec_from_file_location("backup", Path(__file__).with_name("postgres-backup.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class FakeSQL:
    statements = []
    exists = False
    changed_oid = False
    def __init__(self, env):
        self.database = env["PGDATABASE"]
    def __enter__(self):
        return self
    def __exit__(self, *_):
        pass
    def query(self, sql):
        self.statements.append(sql)
        if "server_version_num" in sql:
            return "180006"
        if "server_encoding" in sql:
            return "UTF8"
        if "SELECT count(*) FROM pg_database" in sql:
            return "1" if self.exists else "0"
        if "SELECT oid FROM pg_database" in sql:
            return "42"
        if "FROM pg_sequences" in sql:
            return "[]"
        if "pg_export_snapshot" in sql:
            return "00000003-0000001B-1"
        return ""


class ContainerCleanupTests(unittest.TestCase):
    def test_exact_owned_containers_removed_on_success_failure_and_client_interrupt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            docker = root / "docker"
            docker.write_text('''#!/usr/bin/env python3
import json, os, signal, sys
with open(os.environ["MOCK_LOG"], "a") as output:
    output.write(json.dumps(sys.argv[1:]) + "\\n")
if sys.argv[1:3] == ["context", "inspect"]:
    print("unix:///synthetic/docker.sock")
if sys.argv[1] == "run":
    if os.environ["MOCK_MODE"] == "fail":
        sys.exit(42)
    if os.environ["MOCK_MODE"] == "interrupt":
        os.kill(os.getppid(), signal.SIGTERM)
''')
            # The real backup fixture mounts /tmp noexec. Source a private Bash
            # function and invoke the mock via Python, never execute a temp file.
            bash_env = root / "bash-env"
            bash_env.write_text('docker() { python3 "$MOCK_DOCKER" "$@"; }\n')
            for mode, expected in (("success", 0), ("fail", 42), ("interrupt", 143)):
                log = root / (mode + ".jsonl")
                env = dict(os.environ, BASH_ENV=str(bash_env), MOCK_DOCKER=str(docker),
                           DOCKER_HOST="", MOCK_LOG=str(log), MOCK_MODE=mode)
                result = subprocess.run(["bash", str(Path(__file__).with_name("test-backup-container.sh"))],
                                        env=env, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, expected, (mode, result.stderr))
                calls = [json.loads(line) for line in log.read_text().splitlines()]
                build = next(call for call in calls if call[0] == "build")
                image = build[build.index("-t") + 1]
                self.assertRegex(image, r"^peerloom-backup-validation:[a-f0-9]{24}$")
                nonce = image.split(":")[1]
                owned = ["peerloom-backup-drill-" + nonce, "peerloom-backup-evidence-" + nonce]
                runs = [call for call in calls if call[0] == "run"]
                self.assertEqual(len(runs), 2 if mode == "success" else 1)
                for index, call in enumerate(runs):
                    self.assertEqual(call[call.index("--name") + 1], owned[index])
                    self.assertEqual(call[call.index("--network") + 1], "none")
                self.assertEqual(calls[-2:], [["rm", "-f", *owned], ["image", "rm", image]])


class BackupTests(unittest.TestCase):
    def setUp(self):
        FakeSQL.statements = []
        FakeSQL.exists = False
        self.env = {"PGHOST": "127.0.0.1", "PGPORT": "55432", "PGDATABASE": "fixture", "PGUSER": "peerloom"}
        self.ledger = m.migrations()
        self.facts = {"migrations": self.ledger, "schema_sha256": "a" * 64,
                      "tables": {"devices": {"rows": 2, "sha256": "b" * 64}}, "sequences": []}

    def bundle(self, directory):
        directory.mkdir(mode=0o700)
        archive = directory / "database.dump"
        archive.write_bytes(b"PGDMP-test")
        archive.chmod(0o600)
        meta = {"format": m.BUNDLE_FORMAT, "tool_major": 18, "server_version_num": 180006,
                "archive_bytes": archive.stat().st_size, "archive_sha256": m.digest(archive), "evidence": self.facts}
        m.write_json(directory / "metadata.json", meta)
        m.write_json(directory / "checksums.json", {"database.dump": m.digest(archive),
                                                   "metadata.json": m.digest(directory / "metadata.json")})

    def test_env_rejects_remote_dsn_and_implicit_password(self):
        for changes in ({"PGHOST": "example.org"}, {"PGHOST": "127.0.0.1,example.org"},
                        {"PGDATABASE": "postgresql://user:secret@host/db"}, {"PGPASSWORD": "secret"},
                        {"PGHOSTADDR": "8.8.8.8"}, {"PGSERVICE": "production"}, {"PGPORT": "0"}):
            with self.subTest(changes=changes), self.assertRaises(m.Failure):
                m.connection_env(dict(self.env, **changes))
        env = m.connection_env(dict(self.env, PGOPTIONS="-c log_statement=all"))
        self.assertNotIn("log_statement", env["PGOPTIONS"])
        self.assertEqual(env["PGPASSFILE"], "/dev/null")

    def test_password_file_permissions_and_symlink(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "pgpass"
            path.write_text("private")
            path.chmod(0o600)
            self.assertEqual(m.connection_env(dict(self.env, PGPASSFILE=str(path)))["PGPASSFILE"], str(path))
            path.chmod(0o644)
            with self.assertRaises(m.Failure):
                m.connection_env(dict(self.env, PGPASSFILE=str(path)))
            link = Path(root) / "link"
            link.symlink_to(path)
            with self.assertRaises(m.Failure):
                m.connection_env(dict(self.env, PGPASSFILE=str(link)))

    def test_backup_mode_snapshot_and_no_overwrite(self):
        calls = []
        def tool(args, env, output=None):
            calls.append(args)
            output.write(b"PGDMP-test")
        with tempfile.TemporaryDirectory() as root, mock.patch.object(m, "SQL", FakeSQL), \
             mock.patch.object(m, "tools_major", return_value=18), mock.patch.object(m, "evidence", return_value=self.facts), \
             mock.patch.object(m, "run", side_effect=tool):
            directory = Path(root) / "bundle"
            result = m.backup(directory, self.env)
            self.assertEqual(result["status"], "backup_created")
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            for file in directory.iterdir():
                self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
            self.assertTrue(any(arg.startswith("--snapshot=") for arg in calls[0]))
            self.assertNotIn("--clean", calls[0])
            self.assertEqual(m.load_bundle(directory)["evidence"], self.facts)
            with self.assertRaises(FileExistsError):
                m.backup(directory, self.env)

    def test_sequence_change_prevents_completed_backup(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(m, "SQL", FakeSQL), \
             mock.patch.object(m, "tools_major", return_value=18), mock.patch.object(m, "evidence", return_value=self.facts), \
             mock.patch.object(m, "sequence_evidence", return_value=[["advanced_sequence"]]), \
             mock.patch.object(m, "run", side_effect=lambda args, env, output: output.write(b"dump")):
            directory = Path(root) / "bundle"
            with self.assertRaisesRegex(m.Failure, "SEQUENCE_CHANGED"):
                m.backup(directory, self.env)
            self.assertFalse((directory / "metadata.json").exists())

    def test_bundle_symlink_and_migration_drift_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / "bundle"
            self.bundle(directory)
            link = Path(root) / "link"
            link.symlink_to(directory, target_is_directory=True)
            with self.assertRaisesRegex(m.Failure, "INSECURE_DIRECTORY"):
                m.load_bundle(link)
            with mock.patch.object(m, "migrations", return_value=[]), self.assertRaisesRegex(m.Failure, "MIGRATION_LEDGER_MISMATCH"):
                m.load_bundle(directory)

    def test_tampered_archive_and_metadata_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / "bundle"
            self.bundle(directory)
            (directory / "database.dump").write_bytes(b"changed")
            with self.assertRaisesRegex(m.Failure, "CHECKSUM_MISMATCH"):
                m.load_bundle(directory)

    def test_restore_creates_new_no_clean_and_removes_target(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(m, "SQL", FakeSQL), \
             mock.patch.object(m, "tools_major", return_value=18), mock.patch.object(m, "evidence", return_value=self.facts), \
             mock.patch.object(m, "run") as runner:
            directory = Path(root) / "bundle"
            self.bundle(directory)
            result = m.drill(directory, self.env, "peerloom_drill_test")
            args = runner.call_args.args[0]
            self.assertTrue(result["target_removed"])
            self.assertIn("--single-transaction", args)
            self.assertNotIn("--clean", args)
            self.assertNotIn("--create", args)
            self.assertTrue(any("TEMPLATE template0" in q for q in FakeSQL.statements))
            self.assertTrue(any("DROP DATABASE" in q for q in FakeSQL.statements))

    def test_existing_or_live_target_never_restored_or_dropped(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(m, "SQL", FakeSQL), \
             mock.patch.object(m, "tools_major", return_value=18), mock.patch.object(m, "run") as runner:
            directory = Path(root) / "bundle"
            self.bundle(directory)
            for target in ("fixture", "postgres", "peerloom_drill_existing"):
                FakeSQL.exists = True
                with self.assertRaises(m.Failure):
                    m.drill(directory, self.env, target)
            runner.assert_not_called()
            self.assertFalse(any("CREATE DATABASE" in q or "DROP DATABASE" in q for q in FakeSQL.statements))

    def test_failed_restore_or_evidence_mismatch_cleans_only_created_target(self):
        for fail_restore in (True, False):
            with self.subTest(fail_restore=fail_restore), tempfile.TemporaryDirectory() as root, \
                 mock.patch.object(m, "SQL", FakeSQL), mock.patch.object(m, "tools_major", return_value=18), \
                 mock.patch.object(m, "evidence", return_value={}), \
                 mock.patch.object(m, "run", side_effect=m.Failure("RESTORE_FAILED") if fail_restore else None):
                directory = Path(root) / "bundle"
                self.bundle(directory)
                with self.assertRaises(m.Failure):
                    m.drill(directory, self.env, "peerloom_drill_failed", keep=True)
                self.assertIn('DROP DATABASE "peerloom_drill_failed";', FakeSQL.statements)
                self.assertEqual(len(list(directory.glob("drill-*.json"))), 0)

    def test_explicit_keep_after_success_only(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(m, "SQL", FakeSQL), \
             mock.patch.object(m, "tools_major", return_value=18), mock.patch.object(m, "evidence", return_value=self.facts), \
             mock.patch.object(m, "run"):
            directory = Path(root) / "bundle"
            self.bundle(directory)
            result = m.drill(directory, self.env, "peerloom_drill_keep", keep=True)
            self.assertFalse(result["target_removed"])
            self.assertFalse(any("DROP DATABASE" in q for q in FakeSQL.statements))

    def test_version_mismatch_stops_before_create(self):
        with tempfile.TemporaryDirectory() as root, mock.patch.object(m, "SQL", FakeSQL), \
             mock.patch.object(m, "tools_major", return_value=19), mock.patch.object(m, "run") as runner:
            directory = Path(root) / "bundle"
            self.bundle(directory)
            with self.assertRaisesRegex(m.Failure, "MAJOR_MISMATCH"):
                m.drill(directory, self.env)
            runner.assert_not_called()
            self.assertEqual(FakeSQL.statements, [])

    def test_error_output_never_contains_private_dsn(self):
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(m, "connection_env", side_effect=OSError("postgresql://private:password@private/db")), \
             contextlib.redirect_stderr(stderr):
            self.assertEqual(m.main(["backup", "--directory", "unused", "--local-operator"]), 2)
        self.assertNotIn("password", stderr.getvalue())
        self.assertNotIn("postgresql", stderr.getvalue())

    def test_explicit_operator_and_archive_ack_required(self):
        with mock.patch.object(m, "connection_env") as env, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(m.main(["backup", "--directory", "unused"]), 2)
            self.assertEqual(m.main(["drill", "--directory", "unused", "--local-operator"]), 2)
            env.assert_not_called()

    def test_not_null_name_only_normalization_preserves_all_other_semantics(self):
        source = {"columns": [["requests", "key", True]], "indexes": [], "extensions": [], "functions": [], "triggers": [], "constraints": [
            ["requests", "n", "requests_key_not_null", "NOT NULL key", True, True],
            ["requests", "n", "requests_id_not_null", "NOT NULL id", True, True],
            ["requests", "c", "requests_check", "CHECK (key <> '')", True, True]]}
        original = m.schema_digest(json.dumps(source))
        restored = json.loads(json.dumps(source))
        restored["constraints"][0][2] += "1"
        restored["constraints"].reverse()
        self.assertEqual(m.schema_digest(json.dumps(restored)), original)
        # Do not collapse duplicate constraints or ignore names on checks/FKs/etc.
        mutations = [
            lambda value: value["constraints"][0].__setitem__(3, "NOT NULL other_column"),
            lambda value: value["constraints"][0].__setitem__(4, False),
            lambda value: value["constraints"][0].__setitem__(5, False),
            lambda value: value["constraints"][0].__setitem__(0, "other_table"),
            lambda value: value["constraints"][0].__setitem__(1, "c"),
            lambda value: value["constraints"][2].__setitem__(2, "renamed_check"),
            lambda value: value["constraints"].append(value["constraints"][0].copy()),
            lambda value: value["columns"][0].__setitem__(2, False),
        ]
        for mutate in mutations:
            changed = json.loads(json.dumps(source))
            mutate(changed)
            self.assertNotEqual(m.schema_digest(json.dumps(changed)), original)
        for kind in ("c", "f", "p", "u", "t", "x"):
            named = json.loads(json.dumps(source))
            named["constraints"][0][1] = kind
            before = m.schema_digest(json.dumps(named))
            named["constraints"][0][2] += "1"
            self.assertNotEqual(m.schema_digest(json.dumps(named)), before)

    def test_function_and_trigger_definition_or_enablement_changes_are_detected(self):
        source = {"columns": [], "constraints": [], "indexes": [], "extensions": [],
                  "functions": [["guard", "", "CREATE FUNCTION guard() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NEW; END$$"]],
                  "triggers": [["audit_events", "guard", "CREATE TRIGGER guard AFTER INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION guard()", "O"]]}
        before = m.schema_digest(json.dumps(source))
        changes = (lambda value: value.update(functions=[]), lambda value: value.update(triggers=[]),
                   lambda value: value["functions"][0].__setitem__(2, "different function body"),
                   lambda value: value["triggers"][0].__setitem__(2, "different trigger definition"),
                   lambda value: value["triggers"][0].__setitem__(3, "D"))
        for mutate in changes:
            changed = json.loads(json.dumps(source)); mutate(changed)
            self.assertNotEqual(m.schema_digest(json.dumps(changed)), before)
        source["functions"] *= 129
        with self.assertRaisesRegex(m.Failure, "SCHEMA_OBJECT_LIMIT"):
            m.schema_digest(json.dumps(source))

    def test_v1_evidence_not_silently_accepted_as_v2(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / "bundle"
            self.bundle(directory)
            path = directory / "metadata.json"
            meta = json.loads(path.read_text())
            meta["format"] = "peerloom-local-logical-v1"
            path.write_text(json.dumps(meta))
            sums = directory / "checksums.json"
            manifest = json.loads(sums.read_text())
            manifest["metadata.json"] = m.digest(path)
            sums.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(m.Failure, "INVALID_METADATA"):
                m.load_bundle(directory)

    def test_schema_and_identity_digest_bounds(self):
        class EvidenceDB:
            def query(inner, sql):
                if "FROM pg_sequences" in sql:
                    return "[]"
                if "count(*)" in sql:
                    return "0"
                if "coalesce(jsonb_agg(relname" in sql:
                    return '["devices"]'
                if "coalesce(jsonb_agg(jsonb_build_object" in sql:
                    return json.dumps(self.ledger)
                if sql == m.SCHEMA_SQL:
                    return '{"columns":[],"constraints":[],"indexes":[],"extensions":[],"functions":[],"triggers":[]}'
                return "\n".join(["a" * 64, "b" * 64])
        with mock.patch.object(m, "MAX_ROWS", 1), self.assertRaisesRegex(m.Failure, "ROW_LIMIT"):
            m.evidence(EvidenceDB(), self.ledger)
        facts = m.evidence(EvidenceDB(), self.ledger)
        self.assertEqual(facts["tables"]["devices"]["rows"], 2)
        self.assertNotIn("a" * 64, json.dumps(facts["tables"]))


@unittest.skipUnless(os.environ.get("PEERLOOM_BACKUP_INTEGRATION") == "1", "explicit local PG fixture required")
class PostgresIntegration(unittest.TestCase):
    """在已启动的本机 PG 上创建/删除独立 source/target；不修改原 PGDATABASE。"""
    def test_actual_snapshot_identity_and_restore(self):
        env = m.connection_env()
        admin_env = dict(env, PGDATABASE="postgres")
        source = "peerloom_backup_test_" + uuid.uuid4().hex[:20]
        target = "peerloom_drill_" + uuid.uuid4().hex
        source_created, target_created = False, False
        migrate = Path(os.environ["PEERLOOM_TEST_MIGRATE_BIN"]).resolve()
        has_webhook = m.migrations()[-1]["version"] >= 9
        try:
            with m.SQL(admin_env) as admin:
                admin.query(f'CREATE DATABASE "{source}" TEMPLATE template0;')
                source_created = True
            source_env = dict(env, PGDATABASE=source)
            host = env["PGHOST"]
            if host == "::1":
                host = "[::1]"
            # No password in URL/argv: pgx reads the same explicit PGPASSFILE.
            if host.startswith("/"):
                url = f"postgresql://{quote(env['PGUSER'])}@/{source}?host={quote(host, safe='')}&port={env['PGPORT']}&sslmode=disable"
            else:
                url = f"postgresql://{quote(env['PGUSER'])}@{host}:{env['PGPORT']}/{source}?sslmode=disable"
            migrate_env = dict(source_env, DATABASE_URL=url)
            migrate_env.pop("DATABASE_URL_FILE", None)
            m.run([str(migrate), "--dir", str(m.ROOT / "infra/migrations"), "up"], migrate_env)
            with m.SQL(source_env) as db:
                db.query("""BEGIN;
INSERT INTO tenants(id,name) VALUES ('00000000-0000-4000-8000-000000000001','backup A'),('00000000-0000-4000-8000-000000000002','backup B');
INSERT INTO applications(id,tenant_id,name) VALUES('00000000-0000-4000-8000-000000000003','00000000-0000-4000-8000-000000000001','backup app');
INSERT INTO devices(id,tenant_id,application_id,installation_key_hash,platform,status) VALUES ('00000000-0000-4000-8000-000000000004','00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000003',sha256('installation'::bytea),'linux','revoked');
INSERT INTO device_credentials(tenant_id,device_id,credential_hash,expires_at,revoked_at) VALUES('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000004',sha256('credential'::bytea),now()+interval '1 day',now());
INSERT INTO registration_grants(tenant_id,application_id,secret_hash,expires_at,consumed_at) VALUES('00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000003',sha256('grant'::bytea),now()+interval '1 day',now());
INSERT INTO audit_events(tenant_id,actor_type,action,details) VALUES('00000000-0000-4000-8000-000000000001','operator','backup.fixture','{"恢复":"验证"}');
COMMIT;
CREATE FUNCTION public.peerloom_backup_guard() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NEW; END$$;
CREATE TRIGGER peerloom_backup_guard AFTER INSERT ON public.audit_events FOR EACH ROW EXECUTE FUNCTION public.peerloom_backup_guard();""")
                if has_webhook:
                    db.query("""INSERT INTO webhook_endpoints(tenant_id,url,secret_ref) VALUES('00000000-0000-4000-8000-000000000001','https://synthetic.invalid/webhook','fixture-unused');
INSERT INTO audit_events(tenant_id,actor_type,action,resource_type,resource_id) VALUES('00000000-0000-4000-8000-000000000001','operator','device.revoke','device','00000000-0000-4000-8000-000000000004');""")
            with tempfile.TemporaryDirectory() as root:
                bundle = Path(root) / "backup"
                real_run = m.run
                def mutate_after_snapshot(args, child_env, output=None):
                    if args[0] == "pg_dump" and "--format=custom" in args:
                        with m.SQL(source_env) as writer:
                            writer.query("INSERT INTO tenants(name) VALUES('after exported snapshot');")
                    return real_run(args, child_env, output)
                with mock.patch.object(m, "run", side_effect=mutate_after_snapshot):
                    m.backup(bundle, source_env)
                # Source now has 3 tenants; archive/evidence must both contain snapshot's 2.
                result = m.drill(bundle, source_env, target, keep=True)
                target_created = True
                self.assertFalse(result["target_removed"])
                with m.SQL(source_env) as current_source:
                    source_schema = json.loads(current_source.query(m.SCHEMA_SQL))
                with m.SQL(dict(env, PGDATABASE=target)) as restored:
                    restored_schema = json.loads(restored.query(m.SCHEMA_SQL))
                    self.assertEqual(m.schema_digest(json.dumps(source_schema)), m.schema_digest(json.dumps(restored_schema)))
                    source_nn = {(entry[0], entry[3]): entry[2] for entry in source_schema["constraints"] if entry[1] == "n"}
                    restored_nn = {(entry[0], entry[3]): entry[2] for entry in restored_schema["constraints"] if entry[1] == "n"}
                    print(json.dumps({"schema_version": m.migrations()[-1]["version"],
                                      "tables": len(m.load_bundle(bundle)["evidence"]["tables"]),
                                      "not_null_names_regenerated": sum(source_nn[key] != restored_nn[key] for key in source_nn)}, sort_keys=True))
                    facts = json.loads(restored.query("SELECT jsonb_build_object('tenants',(SELECT count(*) FROM tenants),'revoked_devices',(SELECT count(*) FROM devices WHERE status='revoked'),'revoked_credentials',(SELECT count(*) FROM device_credentials WHERE revoked_at IS NOT NULL),'consumed_grants',(SELECT count(*) FROM registration_grants WHERE consumed_at IS NOT NULL),'audit_rows',(SELECT count(*) FROM audit_events))::text;"))
                    self.assertEqual(facts, dict(tenants=2, revoked_devices=1, revoked_credentials=1, consumed_grants=1, audit_rows=2 if has_webhook else 1))
                    if has_webhook:
                        self.assertEqual(restored.query("SELECT count(*) FROM webhook_deliveries WHERE state='pending';"), "1")
                    with self.assertRaises(m.Failure):
                        restored.query("UPDATE devices SET tenant_id='00000000-0000-4000-8000-000000000002';")
                with self.assertRaisesRegex(m.Failure, "TARGET_ALREADY_EXISTS"):
                    m.drill(bundle, source_env, target)
                corruptions = [
                    "ALTER TABLE devices ALTER COLUMN platform DROP NOT NULL;",
                    "ALTER TABLE audit_events DISABLE TRIGGER peerloom_backup_guard;",
                    "DROP TRIGGER peerloom_backup_guard ON audit_events;",
                    "CREATE OR REPLACE FUNCTION public.peerloom_backup_guard() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NULL; END$$;",
                    "DROP FUNCTION public.peerloom_backup_guard() CASCADE;",
                ]
                if has_webhook:
                    corruptions += [
                        "ALTER TABLE audit_events DISABLE TRIGGER peerloom_webhook_audit_outbox;",
                        "DROP TRIGGER peerloom_webhook_audit_outbox ON audit_events;",
                        "CREATE OR REPLACE FUNCTION public.peerloom_enqueue_webhook_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NEW; END$$;",
                        "DROP FUNCTION public.peerloom_enqueue_webhook_audit() CASCADE;",
                    ]
                for corruption in corruptions:
                    invalid = "peerloom_drill_" + uuid.uuid4().hex
                    def weaken_after_restore(args, child_env, output=None):
                        result = real_run(args, child_env, output)
                        if args[0] == "pg_restore":
                            with m.SQL(child_env) as changed:
                                changed.query(corruption)
                        return result
                    with mock.patch.object(m, "run", side_effect=weaken_after_restore), \
                         self.assertRaisesRegex(m.Failure, "RESTORED_EVIDENCE_MISMATCH"):
                        m.drill(bundle, source_env, invalid)
                    with m.SQL(admin_env) as admin:
                        self.assertEqual(admin.query(f"SELECT count(*) FROM pg_database WHERE datname='{invalid}';"), "0")
                result = m.drill(bundle, source_env)
                self.assertTrue(result["target_removed"])
                with m.SQL(admin_env) as admin:
                    self.assertEqual(admin.query(f"SELECT count(*) FROM pg_database WHERE datname='{result['database']}';"), "0")
        finally:
            with m.SQL(admin_env) as admin:
                if target_created:
                    admin.query(f'DROP DATABASE "{target}";')
                if source_created:
                    admin.query(f'DROP DATABASE "{source}";')


if __name__ == "__main__":
    unittest.main()
