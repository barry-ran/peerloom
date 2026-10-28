#!/usr/bin/env python3
# MIT — Copyright (c) 2026 Peerloom contributors.
"""Linux/macOS 真实子进程测试；不是 Swift/XCTest 或 Apple Keychain 验收。"""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPT = Path(__file__).with_name("watchdog.py")


class WatchdogTests(unittest.TestCase):
    def execute(self, root, code, seconds=2, extra=()):
        command = [sys.executable, str(SCRIPT), "--timeout", str(seconds), "--grace", "0.15",
                   "--log", str(root / "output.log"), "--status", str(root / "status.json"),
                   "--", sys.executable, "-c", code, *map(str, extra)]
        return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)

    def test_success_captures_both_streams_and_redacts_argv(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = self.execute(root, "import sys; print('stdout'); print('stderr',file=sys.stderr)", extra=["private-argv-fixture"])
            self.assertEqual(result.returncode, 0)
            self.assertIn(b"stdout", (root / "output.log").read_bytes())
            self.assertIn(b"stderr", (root / "output.log").read_bytes())
            text = (root / "status.json").read_text()
            self.assertNotIn("private-argv-fixture", text)
            self.assertEqual(json.loads(text)["classification"], "passed")
            self.assertEqual((root / "status.json").stat().st_mode & 0o777, 0o600)

    def test_failure_preserves_original_exit_and_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = self.execute(root, "print('before failure',flush=True); raise SystemExit(7)")
            self.assertEqual(result.returncode, 7)
            self.assertIn(b"before failure", result.stdout)
            self.assertEqual(json.loads((root / "status.json").read_text())["classification"], "failed")

    def test_timeout_kills_term_ignoring_descendant_and_keeps_last_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            heartbeat = root / "heartbeat"
            child = "import pathlib,signal,time,sys; signal.signal(signal.SIGTERM,signal.SIG_IGN); p=pathlib.Path(sys.argv[1]);\nwhile True: p.write_text(str(time.monotonic())); time.sleep(.02)"
            parent = "import signal,subprocess,sys,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]]); print('waiting for owned child',flush=True); time.sleep(100)"
            result = self.execute(root, parent, seconds=0.35, extra=[child, heartbeat])
            self.assertEqual(result.returncode, 124, result.stderr)
            self.assertIn(b"waiting for owned child", (root / "output.log").read_bytes())
            status = json.loads((root / "status.json").read_text())
            self.assertEqual(status["classification"], "timeout")
            self.assertLess(status["elapsed_seconds"], 3)
            value = heartbeat.read_bytes()
            time.sleep(0.15)
            self.assertEqual(heartbeat.read_bytes(), value, "owned descendant survived timeout")

    def test_exited_parent_with_inherited_pipe_is_still_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code = "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(100)']); print('leader exited',flush=True)"
            result = self.execute(root, code, seconds=0.3)
            self.assertEqual(result.returncode, 124)
            self.assertEqual(json.loads((root / "status.json").read_text())["classification"], "timeout")

    def test_interrupt_is_distinct_and_cleans_owned_group(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command = [sys.executable, str(SCRIPT), "--timeout", "5", "--grace", "0.1",
                       "--log", str(root / "output.log"), "--status", str(root / "status.json"),
                       "--", sys.executable, "-c", "import time; print('ready',flush=True); time.sleep(100)"]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 3
                while (not (root / "output.log").exists() or not (root / "output.log").read_bytes()) and time.monotonic() < deadline:
                    time.sleep(0.01)
                process.send_signal(signal.SIGTERM)
                process.communicate(timeout=4)
                self.assertEqual(process.returncode, 143)
                self.assertEqual(json.loads((root / "status.json").read_text())["classification"], "interrupted")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()

    def test_refuses_overwrite_and_missing_program_reports_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "status.json").write_text("original evidence")
            result = self.execute(root, "pass")
            self.assertEqual(result.returncode, 2)
            self.assertEqual((root / "status.json").read_text(), "original evidence")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = subprocess.run([sys.executable, str(SCRIPT), "--timeout", "1", "--log", str(root / "log"),
                                     "--status", str(root / "status.json"), "--", "/nonexistent-peerloom-test-command"], capture_output=True)
            self.assertEqual(result.returncode, 127)
            self.assertEqual(json.loads((root / "status.json").read_text())["classification"], "launch-or-io-error")

    def test_structured_stdout_is_not_contaminated_by_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = subprocess.run([sys.executable, str(SCRIPT), "--timeout", "2", "--log", str(root / "log"),
                                     "--status", str(root / "status.json"), "--stdout", str(root / "stdout"),
                                     "--", sys.executable, "-c", "import sys; print('{}'); print('warning',file=sys.stderr)"], capture_output=True)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(json.loads((root / "stdout").read_text()), {})
            self.assertIn(b"warning", (root / "log").read_bytes())
            self.assertIn("finished_at", json.loads((root / "status.json").read_text()))

    def test_cleanup_does_not_invoke_xcode_validation_or_existing_devices(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "SwiftPackage").mkdir()
            binary = root / "bin"
            binary.mkdir()
            for name, script in (("uname", "#!/bin/sh\nprintf 'Darwin\\n'\n"),
                                 ("xcodebuild", "#!/bin/sh\nexit 99\n"),
                                 ("xcrun", "#!/bin/sh\nexit 99\n")):
                path = binary / name
                path.write_text(script)
                path.chmod(0o700)
            env = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ["PATH"],
                       PEERLOOM_REPO_ROOT=str(root), PEERLOOM_APPLE_OUTPUT=str(root))
            result = subprocess.run(["bash", str(SCRIPT.with_name("test-native.sh")), "--stage", "cleanup"],
                                    env=env, capture_output=True, timeout=3)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
