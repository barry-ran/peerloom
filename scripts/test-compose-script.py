#!/usr/bin/env python3
"""验证联调脚本的秘密处理与清理，不代替真实 Compose 运行验收。"""
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import unittest
import sys

MOCK = r'''#!/usr/bin/env python3
import json, os, pathlib, stat, subprocess, sys
name = pathlib.Path(sys.argv[0]).name
if name == "test-lifecycle.sh":
    admin = pathlib.Path(sys.argv[sys.argv.index("--admin-fixture")+1])
    assert stat.S_IMODE(admin.stat().st_mode) == 0o600
    assert json.loads(admin.read_text())["service_credential"] == os.environ["TEST_EPHEMERAL_GRANT"]
    secret = pathlib.Path(sys.argv[sys.argv.index("--shared-secret-file")+1])
    assert stat.S_IMODE(secret.stat().st_mode) == 0o600
    pathlib.Path("lifecycle-test-invoked").touch()
    sys.exit(7 if os.environ["TEST_FAIL_TARGET"] == "lifecycle" else 0)
if name == "test-managed-relay.sh":
    admin = pathlib.Path(sys.argv[sys.argv.index("--lease-admin-fixture")+1])
    assert stat.S_IMODE(admin.stat().st_mode) == 0o600
    assert json.loads(admin.read_text())["service_credential"] == os.environ["TEST_EPHEMERAL_GRANT"]
    p = pathlib.Path(sys.argv[sys.argv.index("--pair-fixture")+1])
    secret = pathlib.Path(sys.argv[sys.argv.index("--shared-secret-file")+1])
    assert stat.S_IMODE(p.stat().st_mode) == 0o600 and stat.S_IMODE(secret.stat().st_mode) == 0o600
    registry = pathlib.Path(os.environ["PEERLOOM_TEST_RELAY_REGISTRY_FILE"])
    assert stat.S_IMODE(registry.stat().st_mode) == 0o444 and stat.S_IMODE(registry.parent.stat().st_mode) == 0o700
    assert json.loads(registry.read_text())["bindings"]["ci-managed-relay"]["secret"] == secret.read_text()
    pathlib.Path("relay-private-proof").write_text(secret.read_text())
    record = pathlib.Path("fixture-paths")
    previous = record.read_text().splitlines()
    assert str(p) not in previous and all(not pathlib.Path(old).exists() for old in previous)
    record.write_text("\n".join(previous + [str(p)]))
    pathlib.Path("relay-test-invoked").touch()
    sys.exit(7 if os.environ["TEST_FAIL_TARGET"] == "relay" else 0)
if name == "python3":
    if len(sys.argv) > 1 and sys.argv[1].endswith("run-service.py"):
        p = pathlib.Path(os.environ["TEST_SIGNAL_FIXTURE_FILE"])
        assert p.is_absolute() and stat.S_IMODE(p.stat().st_mode) == 0o600
        assert json.loads(p.read_text())["source"]["device_credential"] == os.environ["TEST_EPHEMERAL_GRANT"]
        assert os.environ["TEST_IDENTITY_BASE_URL"] == "http://127.0.0.1:18080"
        record = pathlib.Path("fixture-paths")
        previous = record.read_text().splitlines()
        assert str(p) not in previous and all(not pathlib.Path(old).exists() for old in previous)
        record.write_text("\n".join(previous + [str(p)]))
        pathlib.Path("ffi-test-invoked").touch()
        sys.exit(7 if os.environ["TEST_FAIL_TARGET"] == "ffi" else 0)
    if len(sys.argv) > 1 and sys.argv[1].endswith("test-management.py"):
        for argument in ("--admin-fixture", "--foreign-admin-fixture", "--read-fixture"):
            if argument not in sys.argv:
                continue
            path = pathlib.Path(sys.argv[sys.argv.index(argument) + 1])
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
            assert json.loads(path.read_text())["service_credential"] == os.environ["TEST_EPHEMERAL_GRANT"]
        output = pathlib.Path(sys.argv[sys.argv.index("--pair-output") + 1])
        assert not output.exists()
        output.write_text(json.dumps({side: {"application_id": side, "device_id": side, "device_credential": os.environ["TEST_EPHEMERAL_GRANT"], "expires_at": "test-expiry"} for side in ("source", "target")}))
        output.chmod(0o600)
        pathlib.Path("management-test-invoked").touch()
        sys.exit(9 if os.environ["TEST_FAIL_TARGET"] == "management" else 0)
    sys.exit(subprocess.run([os.environ["REAL_PYTHON"], *sys.argv[1:]], input=sys.stdin.read(), text=True).returncode)
if name == "docker":
    if "device-admin" in sys.argv:
        assert "--offline" in sys.argv
        print(json.dumps({"tenant_id": "00000000-0000-4000-8000-000000000001", "service_credential": os.environ["TEST_EPHEMERAL_GRANT"]}))
    if "device-bootstrap" in sys.argv:
        if "--pair" in sys.argv:
            print(json.dumps({side: {"application_id": side, "device_id": side, "device_credential": os.environ["TEST_EPHEMERAL_GRANT"], "expires_at": "test-expiry"} for side in ("source", "target")}))
        else:
            print(json.dumps({"application_id": "test-app", "registration_grant": os.environ["TEST_EPHEMERAL_GRANT"]}))
    if "down" in sys.argv:
        assert not list(pathlib.Path(".secrets").glob("identity-fixture.*")), "fixture survived cleanup"
        assert not list(pathlib.Path(".secrets").glob("management-fixture.*")), "management fixture survived cleanup"
        pathlib.Path("cleanup-completed").touch()
elif name == "curl" and "%{http_code}" in sys.argv:
    print("404" if sys.argv[-1].endswith("/metrics") else "401", end="")
elif name == "go":
    assert os.environ.get("TEST_DATABASE_URL") and os.environ.get("TEST_REDIS_URL")
elif name == "cargo":
    target = "sdk" if "sdk_service" in sys.argv else "pair" if "authorized_pair" in sys.argv else "identity"
    pair = target != "identity"
    p = pathlib.Path(os.environ["TEST_SIGNAL_FIXTURE_FILE" if pair else "TEST_IDENTITY_FIXTURE_FILE"])
    if target == "sdk" and p.parent.name.startswith("management-fixture."):
        target = "managed_sdk"
    assert p.is_absolute() and stat.S_IMODE(p.stat().st_mode) == 0o600
    data = json.loads(p.read_text())
    assert (data["source"]["device_credential"] if pair else data["registration_grant"]) == os.environ["TEST_EPHEMERAL_GRANT"]
    assert os.environ["TEST_IDENTITY_BASE_URL"] == "http://127.0.0.1:18080"
    assert (pair or "identity_service" in sys.argv) and "--ignored" in sys.argv
    pathlib.Path("../../" + target + "-test-invoked").touch()
    record = pathlib.Path("../../fixture-paths")
    previous = record.read_text().splitlines() if record.exists() else []
    assert str(p) not in previous, "each integration needs a fresh fixture"
    assert all(not pathlib.Path(old).exists() for old in previous), "previous fixture must already be removed"
    record.write_text("\n".join(previous + [str(p)]))
    sys.exit(int(os.environ["TEST_CARGO_EXIT"]) if target == os.environ["TEST_FAIL_TARGET"] else 0)
'''


class ComposeScriptTest(unittest.TestCase):
    def run_script(self, exit_code, fail_target="identity"):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir()
            (root / "src/device-sdk").mkdir(parents=True)
            (root / ".secrets").mkdir(mode=0o700)
            (root / "bin").mkdir()
            password, grant = secrets.token_hex(32), secrets.token_hex(32)
            (root / ".secrets/database_url").write_text(f"postgres://peerloom:{password}@postgres:5432/peerloom")
            (root / ".secrets/redis_password").write_text(password)
            script = root / "scripts/test-compose.sh"
            shutil.copyfile(Path(__file__).with_name("test-compose.sh"), script)
            for name in ("docker", "curl", "go", "cargo", "python3", "test-managed-relay.sh", "test-lifecycle.sh"):
                executable = root / ("scripts" if name in ("test-managed-relay.sh", "test-lifecycle.sh") else "bin") / name
                executable.write_text(MOCK.replace("#!/usr/bin/env python3", "#!" + sys.executable, 1))
                executable.chmod(0o700)
            env = {**os.environ, "PATH": str(root / "bin") + os.pathsep + os.environ["PATH"],
                   "REAL_PYTHON": sys.executable, "TEST_EPHEMERAL_GRANT": grant, "TEST_CARGO_EXIT": str(exit_code), "TEST_FAIL_TARGET": fail_target}
            result = subprocess.run(["bash", "-x", str(script)], env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, exit_code, result.stderr)
            self.assertTrue((root / "identity-test-invoked").exists())
            self.assertTrue((root / "cleanup-completed").exists())
            if exit_code == 0 or fail_target in ("pair", "sdk", "management", "managed_sdk", "ffi", "relay", "lifecycle"):
                self.assertTrue((root / "pair-test-invoked").exists())
            if exit_code == 0 or fail_target in ("sdk", "management", "managed_sdk", "ffi", "relay", "lifecycle"):
                self.assertTrue((root / "sdk-test-invoked").exists())
                self.assertEqual(len((root / "fixture-paths").read_text().splitlines()), 6 if exit_code == 0 or fail_target in ("relay", "lifecycle") else 5 if fail_target == "ffi" else 4 if fail_target == "managed_sdk" else 3)
            if exit_code == 0 or fail_target in ("management", "managed_sdk", "ffi", "relay", "lifecycle"):
                self.assertTrue((root / "management-test-invoked").exists())
            if exit_code == 0 or fail_target in ("managed_sdk", "ffi", "relay", "lifecycle"):
                self.assertTrue((root / "managed_sdk-test-invoked").exists())
            if exit_code == 0 or fail_target in ("ffi", "relay", "lifecycle"):
                self.assertTrue((root / "ffi-test-invoked").exists())
            if exit_code == 0 or fail_target in ("relay", "lifecycle"):
                self.assertTrue((root / "relay-test-invoked").exists())
                self.assertNotIn((root / "relay-private-proof").read_text(), result.stdout + result.stderr)
            if exit_code == 0 or fail_target == "lifecycle":
                self.assertTrue((root / "lifecycle-test-invoked").exists())
            self.assertEqual(list((root / ".secrets").glob("relay-fixture.*")), [])
            self.assertNotIn(password, result.stdout + result.stderr)
            self.assertNotIn(grant, result.stdout + result.stderr)
            self.assertEqual(list((root / ".secrets").glob("identity-fixture.*")), [])

    def test_lifecycle_failure_still_cleans_credentials(self):
        self.run_script(7, "lifecycle")

    def test_success_cleans_fixture_without_logging_secrets(self):
        self.run_script(0)

    def test_failed_relay_still_cleans_credentials(self):
        self.run_script(7, "relay")

    def test_failed_ffi_still_cleans_credentials(self):
        self.run_script(7, "ffi")

    def test_failed_management_still_cleans_credentials(self):
        self.run_script(9, "management")

    def test_failed_managed_sdk_still_cleans_credentials(self):
        self.run_script(7, "managed_sdk")

    def test_failed_sdk_test_still_cleans_fixture(self):
        self.run_script(7, "sdk")

    def test_failed_pair_test_still_cleans_fixture(self):
        self.run_script(7, "pair")

    def test_failed_identity_test_still_cleans_fixture(self):
        self.run_script(7)


if __name__ == "__main__":
    unittest.main()
