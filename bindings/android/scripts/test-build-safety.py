#!/usr/bin/env python3
"""Small host-only negative tests; never starts a real emulator or modifies KVM."""
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent

def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + ".py"))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

checksums = module("verify-checksums")
kvm = module("kvm-access")
ACL = "# file: /dev/kvm\n# owner: root\n# group: kvm\nuser::rw-\ngroup::rw-\nother::---\n"

class Checksums(unittest.TestCase):
    def fixture(self, path):
        entries = []
        for name in sorted(checksums.FILES):
            data = name.encode()
            (path / name).write_bytes(data)
            entries.append(hashlib.sha256(data).hexdigest() + "  " + name)
        (path / "SHA256SUMS").write_text("\n".join(entries) + "\n")

    def test_exact_set(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            self.fixture(path)
            checksums.verify(path)

    def test_missing_extra_tampered_duplicate_and_path_rejected(self):
        for case in ("missing", "extra", "tampered", "entry", "duplicate", "traversal", "symlink"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp:
                path = Path(temp)
                self.fixture(path)
                manifest = path / "SHA256SUMS"
                apk = path / "sample-debug.apk"
                if case == "missing":
                    apk.unlink()
                elif case == "extra":
                    (path / "unlisted.apk").write_text("extra")
                elif case == "tampered":
                    apk.write_text("tampered")
                elif case == "entry":
                    manifest.write_text("\n".join(manifest.read_text().splitlines()[1:]) + "\n")
                elif case == "duplicate":
                    manifest.write_text(manifest.read_text() + manifest.read_text().splitlines()[0] + "\n")
                elif case == "traversal":
                    manifest.write_text(manifest.read_text().replace("sample-debug.apk", "../sample-debug.apk"))
                else:
                    apk.unlink()
                    apk.symlink_to(path / "library-release.aar")
                with self.assertRaises(ValueError):
                    checksums.verify(path)

class KvmAccess(unittest.TestCase):
    def test_existing_access_is_not_modified(self):
        with tempfile.TemporaryDirectory() as temp:
            calls = []
            kvm.prepare(Path(temp), run=lambda args: calls.append(args), access=lambda: True)
            self.assertEqual(calls, [])
            self.assertFalse(kvm.snapshot_path(Path(temp)).exists())

    def test_only_current_user_acl_and_restore(self):
        with tempfile.TemporaryDirectory() as temp:
            calls = []
            def run(args):
                calls.append(args)
                return ACL if args[0] == "getfacl" else ""
            access = iter([False, True])
            path = Path(temp)
            kvm.prepare(path, run, lambda: next(access))
            self.assertEqual(calls[1], ["sudo", "--non-interactive", "setfacl", "-n", "-m", f"u:{os.getuid()}:rw", "/dev/kvm"])
            kvm.restore(path, run)
            self.assertEqual(calls[2], ["sudo", "--non-interactive", "setfacl", "--restore=" + str(kvm.snapshot_path(path))])
            self.assertFalse(kvm.snapshot_path(path).exists())

    def test_denied_access_fails_without_broad_fallback(self):
        with tempfile.TemporaryDirectory() as temp:
            calls = []
            def run(args):
                calls.append(args)
                return ACL if args[0] == "getfacl" else ""
            with self.assertRaises(PermissionError):
                kvm.prepare(Path(temp), run, lambda: False)
            self.assertEqual(len(calls), 2)
            self.assertFalse(any("chmod" in item or "666" in item for args in calls for item in args))
            # Snapshot remains available for the job's always-cleanup step.
            self.assertTrue(kvm.snapshot_path(Path(temp)).is_file())
            kvm.restore(Path(temp), run)

    def test_restrictive_mask_cannot_unmask_other_users(self):
        with tempfile.TemporaryDirectory() as temp:
            calls = []
            def run(args):
                calls.append(args)
                return ACL + "mask::r--\n"
            with self.assertRaises(PermissionError):
                kvm.prepare(Path(temp), run, lambda: False)
            self.assertEqual(calls, [["getfacl", "-p", "/dev/kvm"]])
            self.assertFalse(kvm.snapshot_path(Path(temp)).exists())

    def test_missing_acl_tool_has_no_fallback_and_foreign_restore_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            def missing(_):
                raise FileNotFoundError("mock getfacl missing")
            with self.assertRaises(FileNotFoundError):
                kvm.prepare(path, missing, lambda: False)
            self.assertFalse(kvm.snapshot_path(path).exists())
            saved = kvm.snapshot_path(path)
            saved.write_text(ACL + "# file: /dev/other\nuser::rw-\n")
            saved.chmod(0o600)
            with self.assertRaises(ValueError):
                kvm.restore(path, lambda _: self.fail("foreign restore executed"))

class EmulatorOwnership(unittest.TestCase):
    def run_mock(self, collision):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            binary = path / "bin"
            binary.mkdir()
            log = path / "adb.log"
            (binary / "adb").write_text('''#!/usr/bin/env python3
import json,os,sys
args=sys.argv[1:]
with open(os.environ['TEST_ADB_LOG'],'a') as out:out.write(json.dumps(args)+'\\n')
if args==['devices']:
 print('List of devices attached')
 if os.environ['TEST_COLLISION']=='1':print('emulator-5580\\tdevice')
 sys.exit(0)
assert args[:2]==['-s','emulator-5580'],args
args=args[2:]
if args==['wait-for-device']:sys.exit(0)
if args==['shell','getprop','sys.boot_completed']:print('1');sys.exit(0)
if args==['emu','avd','name']:print('foreign-user-avd\\nOK');sys.exit(0)
sys.exit(99)
''')
            (binary / "avdmanager").write_text("#!/bin/sh\ncat >/dev/null\n")
            (binary / "emulator").write_text("#!/usr/bin/env python3\nimport time\ntime.sleep(60)\n")
            for command in binary.iterdir():
                command.chmod(0o755)
            env = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ["PATH"], RUNNER_TEMP=temp, TEST_ADB_LOG=str(log), TEST_COLLISION="1" if collision else "0")
            result = subprocess.run(["bash", str(ROOT / "emulator.sh"), "4096", "mock-system-image"], env=env, capture_output=True, text=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("refuse existing emulator serial" if collision else "refuse foreign emulator identity", result.stderr)
            calls = log.read_text()
            self.assertNotIn('"kill"', calls)
            self.assertNotIn('"install"', calls)
            if collision:
                self.assertEqual(len(calls.splitlines()), 1)

    def test_existing_serial_refuses_launch_and_cleanup(self):
        self.run_mock(True)

    def test_foreign_serial_identity_never_receives_cleanup_or_install(self):
        self.run_mock(False)

if __name__ == "__main__":
    unittest.main()
