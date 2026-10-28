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

MOCK = r'''#!/usr/bin/env python3
import json, os, pathlib, stat, sys
name = pathlib.Path(sys.argv[0]).name
if name == "docker":
    if "device-bootstrap" in sys.argv:
        if "--pair" in sys.argv:
            print(json.dumps({side: {"application_id": side, "device_id": side, "device_credential": os.environ["TEST_EPHEMERAL_GRANT"], "expires_at": "test-expiry"} for side in ("source", "target")}))
        else:
            print(json.dumps({"application_id": "test-app", "registration_grant": os.environ["TEST_EPHEMERAL_GRANT"]}))
    if "down" in sys.argv:
        assert not list(pathlib.Path(".secrets").glob("identity-fixture.*")), "fixture survived cleanup"
        pathlib.Path("cleanup-completed").touch()
elif name == "curl" and "%{http_code}" in sys.argv:
    print("404" if sys.argv[-1].endswith("/metrics") else "401", end="")
elif name == "go":
    assert os.environ.get("TEST_DATABASE_URL") and os.environ.get("TEST_REDIS_URL")
elif name == "cargo":
    pair = "authorized_pair" in sys.argv
    p = pathlib.Path(os.environ["TEST_SIGNAL_FIXTURE_FILE" if pair else "TEST_IDENTITY_FIXTURE_FILE"])
    assert p.is_absolute() and stat.S_IMODE(p.stat().st_mode) == 0o600
    data = json.loads(p.read_text())
    assert (data["source"]["device_credential"] if pair else data["registration_grant"]) == os.environ["TEST_EPHEMERAL_GRANT"]
    assert os.environ["TEST_IDENTITY_BASE_URL"] == "http://127.0.0.1:18080"
    assert (pair or "identity_service" in sys.argv) and "--ignored" in sys.argv
    pathlib.Path("../../pair-test-invoked" if pair else "../../identity-test-invoked").touch()
    sys.exit(int(os.environ["TEST_CARGO_EXIT"]) if pair == (os.environ["TEST_FAIL_TARGET"] == "pair") else 0)
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
            for name in ("docker", "curl", "go", "cargo"):
                executable = root / "bin" / name
                executable.write_text(MOCK)
                executable.chmod(0o700)
            env = {**os.environ, "PATH": str(root / "bin") + os.pathsep + os.environ["PATH"],
                   "TEST_EPHEMERAL_GRANT": grant, "TEST_CARGO_EXIT": str(exit_code), "TEST_FAIL_TARGET": fail_target}
            result = subprocess.run(["bash", "-x", str(script)], env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, exit_code, result.stderr)
            self.assertTrue((root / "identity-test-invoked").exists())
            self.assertTrue((root / "cleanup-completed").exists())
            if exit_code == 0 or fail_target == "pair":
                self.assertTrue((root / "pair-test-invoked").exists())
            self.assertNotIn(password, result.stdout + result.stderr)
            self.assertNotIn(grant, result.stdout + result.stderr)
            self.assertEqual(list((root / ".secrets").glob("identity-fixture.*")), [])

    def test_success_cleans_fixture_without_logging_secrets(self):
        self.run_script(0)

    def test_failed_pair_test_still_cleans_fixture(self):
        self.run_script(7, "pair")

    def test_failed_identity_test_still_cleans_fixture(self):
        self.run_script(7)


if __name__ == "__main__":
    unittest.main()
