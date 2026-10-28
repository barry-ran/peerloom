#!/usr/bin/env python3
"""仅验证TURN脚本隔离/秘密清理；真实中继必须由CI的test-turn.sh验证。"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

MOCK = r'''#!/usr/bin/env python3
import json, os, pathlib, re, stat, subprocess, sys
name = pathlib.Path(sys.argv[0]).name
root = pathlib.Path(os.environ["TEST_ROOT"])
if name == "python3":
    source = sys.stdin.read()
    if "isolated TURN UDP readiness failed" in source:
        sys.exit(0)  # 本测试不声称执行网络探活。
    sys.exit(subprocess.run([os.environ["REAL_PYTHON"], *sys.argv[1:]], input=source, text=True).returncode)
if name == "docker":
    if "build" in sys.argv:
        recipe = sys.stdin.read()
        image = sys.argv[sys.argv.index("--tag") + 1]
        assert re.fullmatch(r"[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", image)
        assert "@sha256:bbefd3e1" in recipe and "cat /usr/bin/turnserver > /tmp/turnserver-unprivileged" in recipe
        assert "USER nobody:nogroup" in recipe and "sha256sum /usr/bin/turnserver" in recipe
        assert sys.argv[sys.argv.index("--network") + 1] == "none"
        assert sys.argv[-1] == "-"
        (root / "image-built").touch()
        fixture = next((root / "temp").iterdir())
        (root / "private-proof").write_text(json.dumps({"fixture": str(fixture), "password": (fixture / "password").read_text()}))
        if os.environ["TEST_FAIL"] == "build":
            sys.exit(8)
    if "run" in sys.argv:
        args = sys.argv
        assert args[args.index("--network") + 1] == "host"
        assert args[args.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}"
        assert "--read-only" in args and "--cap-drop" in args and "no-new-privileges:true" in args
        assert args[args.index("--entrypoint") + 1] == "/usr/bin/turnserver"
        assert (root / "image-built").exists()
        assert any(arg.startswith("peerloom-turn-test:") for arg in args)
        mount = args[args.index("--mount") + 1]
        config = pathlib.Path(mount.split("src=", 1)[1].split(",", 1)[0])
        assert stat.S_IMODE(config.stat().st_mode) == 0o600
        assert stat.S_IMODE(config.parent.stat().st_mode) == 0o700
        content = config.read_text()
        for required in ("listening-ip=127.0.0.1", "relay-ip=127.0.0.1", "min-port=55000", "max-port=55031", "lt-cred-mech", "cli=0"):
            assert required in content
        (root / "private-proof").write_text(json.dumps({"fixture": str(config.parent), "password": (config.parent / "password").read_text()}))
        if os.environ["TEST_FAIL"] == "docker":
            sys.exit(9)
    elif "logs" in sys.argv:
        proof = json.loads((root / "private-proof").read_text())
        print("ERROR: diagnostic-redaction-test " + proof["password"])
    elif "inspect" in sys.argv:
        print("TURN state=exited exit=1 oom=false")
    elif "image" in sys.argv:
        (root / "image-cleaned").touch()
    elif "rm" in sys.argv:
        (root / "container-cleaned").touch()
if name == "cargo":
    password = pathlib.Path(os.environ["TEST_TURN_CREDENTIAL_FILE"])
    assert password.is_absolute() and stat.S_IMODE(password.stat().st_mode) == 0o600
    assert os.environ["TEST_TURN_URL"] == "turn:127.0.0.1:53478?transport=udp"
    assert "turn_pair" in sys.argv and "--ignored" in sys.argv
    (root / "test-invoked").touch()
    if os.environ["TEST_FAIL"] == "cargo":
        sys.exit(7)
'''


class TurnScriptTest(unittest.TestCase):
    def exercise(self, failure, expected):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir()
            (root / "src/device-sdk").mkdir(parents=True)
            (root / "bin").mkdir()
            (root / "temp").mkdir()
            script = root / "scripts/test-turn.sh"
            shutil.copyfile(Path(__file__).with_name("test-turn.sh"), script)
            for name in ("docker", "cargo", "python3"):
                executable = root / "bin" / name
                # 固定真实Python解释器，避免mock python3递归调用自身。
                executable.write_text(MOCK.replace("#!/usr/bin/env python3", "#!" + sys.executable, 1))
                executable.chmod(0o700)
            environment = {**os.environ, "PATH": str(root / "bin") + os.pathsep + os.environ["PATH"],
                           "TEST_ROOT": str(root), "REAL_PYTHON": sys.executable,
                           "TEST_FAIL": failure, "TMPDIR": str(root / "temp")}
            result = subprocess.run(["bash", "-x", str(script)], env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, expected, result.stderr)
            self.assertTrue((root / "container-cleaned").exists())
            self.assertTrue((root / "image-cleaned").exists())
            self.assertEqual(list((root / "temp").iterdir()), [])
            import json
            proof = json.loads((root / "private-proof").read_text())
            self.assertNotIn(proof["password"], result.stdout + result.stderr)
            if failure:
                self.assertIn("diagnostic-redaction-test [redacted]", result.stderr)
            if failure not in ("docker", "build"):
                self.assertTrue((root / "test-invoked").exists())

    def test_success(self):
        self.exercise("", 0)

    def test_cargo_failure(self):
        self.exercise("cargo", 7)

    def test_build_failure(self):
        self.exercise("build", 8)

    def test_container_failure(self):
        self.exercise("docker", 9)


if __name__ == "__main__":
    unittest.main()
