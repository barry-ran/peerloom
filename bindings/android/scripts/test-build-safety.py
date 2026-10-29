#!/usr/bin/env python3
"""Small host-only negative tests; never starts a real emulator or modifies KVM."""
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parent

def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + ".py"))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

memory = module("emulator-memory")
checksums = module("verify-checksums")
kvm = module("kvm-access")
artifacts = module("verify-artifacts")
ACL = "# file: /dev/kvm\n# owner: root\n# group: kvm\nuser::rw-\ngroup::rw-\nother::---\n"

class PinnedEmulator(unittest.TestCase):
    SHA256 = "b08fc43d8608d2955f607f1b287beb525041e730086bdca3af152accac3af9c1"

    def install_script(self):
        lines = (ROOT.parents[2]/'.github/workflows/android.yml').read_text().splitlines()
        matches = [index for index, line in enumerate(lines)
                   if line == '      - name: 安装官方模拟器与固定API镜像']
        self.assertEqual(len(matches), 1)
        start = matches[0]+1
        self.assertEqual(lines[start], '        run: |')
        body = []
        for line in lines[start+1:]:
            if line and not line.startswith('          '):
                break
            body.append(line[10:] if line else '')
        self.assertTrue(body)
        script = '\n'.join(body)+'\n'
        self.assertIn('emulator-linux_x64-16428233.zip', script)
        self.assertIn(self.SHA256, script)
        self.assertIn('timeout 600 curl', script)
        self.assertIn('--connect-timeout 20 --max-time 600', script)
        self.assertNotIn("sdkmanager\" 'emulator'", script)
        self.assertNotIn('echo "$ANDROID_HOME/emulator"', script)
        self.assertLess(script.index('sha256sum --strict --check'), script.index('unzip -q'))
        self.assertLess(script.index('cat "$emulator_root/emulator/source.properties"'), script.index('grep -Eq'))
        return script[script.index('emulator_root='):]

    def run_install(self, version='37.2.12', image_revision='7', corrupt=False, image_flavor='google_apis'):
        script = self.install_script()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sdk = root/'sdk'
            existing = sdk/'emulator/source.properties'
            existing.parent.mkdir(parents=True)
            existing.write_text('runner emulator must remain untouched')
            image = sdk/'system-images/android-36'/image_flavor/'x86_64/source.properties'
            image.parent.mkdir(parents=True)
            image.write_text('Pkg.Revision = '+image_revision+'\n')
            archive = root/'fixture.zip'
            with zipfile.ZipFile(archive, 'w') as package:
                package.writestr('emulator/source.properties', 'Pkg.Revision = '+version+'\n')
                info = zipfile.ZipInfo('emulator/emulator')
                info.external_attr = 0o100755 << 16
                package.writestr(info, '#!/bin/sh\necho pinned-emulator\n')
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            if corrupt:
                archive.write_bytes(archive.read_bytes()+b'tampered')
            binary = root/'bin'
            binary.mkdir()
            curl = binary/'curl'
            curl.write_text('#!/bin/sh\nwhile [ "$1" != --output ]; do shift; done\ncp "$FIXTURE_ZIP" "$2"\n')
            curl.chmod(0o755)
            paths = root/'github-path'
            paths.touch()
            runner = root/'runner'
            runner.mkdir()
            script = script.replace(self.SHA256, digest).replace("${{ matrix.page == 16384 && 'google_apis_ps16k' || 'google_apis' }}", image_flavor)
            env = {**os.environ, 'PATH': str(binary)+os.pathsep+os.environ['PATH'],
                   'ANDROID_HOME': str(sdk), 'RUNNER_TEMP': str(runner),
                   'GITHUB_PATH': str(paths), 'FIXTURE_ZIP': str(archive)}
            result = subprocess.run(['bash', '-euo', 'pipefail', '-c', script], env=env,
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(existing.read_text(), 'runner emulator must remain untouched')
            success = version == '37.2.12' and image_revision == '7' and not corrupt
            self.assertEqual(result.returncode == 0, success, result.stdout+result.stderr)
            if success:
                selected = paths.read_text().strip()
                self.assertTrue(selected.startswith(str(runner)+'/peerloom-emulator.'))
                self.assertEqual(Path(selected).name, 'emulator')
                command = subprocess.run(['bash', '-c', 'command -v emulator; emulator'],
                                         env={**env, 'PATH': selected+os.pathsep+env['PATH']},
                                         capture_output=True, text=True, check=True)
                self.assertEqual(command.stdout.splitlines(), [selected+'/emulator', 'pinned-emulator'])
                self.assertFalse(list(runner.rglob('*.zip')))
            else:
                self.assertEqual(paths.read_text(), '')
                self.assertEqual(list(runner.iterdir()), [])
            if not corrupt:
                self.assertIn('Pkg.Revision = '+version, result.stdout)
                self.assertIn('Pkg.Revision = '+image_revision, result.stdout)

    def test_fixed_archive_selects_isolated_binary(self):
        for flavor in ('google_apis', 'google_apis_ps16k'):
            with self.subTest(image=flavor):
                self.run_install(image_flavor=flavor)

    def test_corrupt_archive_fails_before_unpack_and_path_selection(self):
        self.run_install(corrupt=True)

    def test_wrong_emulator_version_fails_with_diagnostic(self):
        self.run_install(version='37.2.13')

    def test_wrong_system_image_revision_fails_with_diagnostic(self):
        self.run_install(image_revision='8')

class NativeVendorInputs(unittest.TestCase):
    def test_every_workspace_path_patch_invalidates_native_build(self):
        import tomllib
        repo = ROOT.parents[2]
        patches = tomllib.loads((repo/'src/device-sdk/Cargo.toml').read_text(encoding='utf-8'))['patch']['crates-io']
        script = (ROOT.parent/'library/build.gradle.kts').read_text(encoding='utf-8')
        for name, value in patches.items():
            vendor = value['path'].removesuffix('/crate')
            self.assertIn('inputs.files(fileTree(rootProject.projectDir.resolve("'+vendor+'")))', script, name)
        self.assertEqual(set(patches), {'nix', 'rtc', 'webrtc'})

    def test_missing_webrtc_input_is_rejected(self):
        from unittest.mock import patch
        original = Path.read_text
        target = ROOT.parent/'library/build.gradle.kts'
        def missing(path, *args, **kwargs):
            text = original(path, *args, **kwargs)
            if path == target:
                text = '\n'.join(line for line in text.splitlines() if 'third_party/rust/webrtc-' not in line)
            return text
        # Call the same contract against an actual omitted input, not a permissive fallback.
        with patch.object(Path, 'read_text', missing), self.assertRaises(AssertionError):
            self.test_every_workspace_path_patch_invalidates_native_build()

class EmulatorMemory(unittest.TestCase):
    def test_fixed_4g_avd_has_readonly_host_memory_admission(self):
        self.assertEqual(memory.validate("MemTotal: 16777216 kB\nMemAvailable: 8388608 kB\n"), (16384, 8192))
        script = (ROOT / "emulator.sh").read_text()
        self.assertIn("-memory 4096 -cores 2", script)
        self.assertLess(script.index("/emulator-memory.py"), script.index("avdmanager create"))

    def test_low_missing_malformed_or_impossible_ram_is_rejected(self):
        for text in ("", "MemTotal: 16777216 kB\nMemAvailable: 4194304 kB\n",
                     "MemTotal: 16777216 kB\nMemAvailable: 8388608 MB\n",
                     "MemTotal: 4194304 kB\nMemAvailable: 8388608 kB\n",
                     "MemTotal: 16777216 kB\nMemAvailable: 8388608 kB\nMemAvailable: 8388608 kB\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                memory.validate(text)

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

    def evidence_fixture(self, path):
        self.fixture(path)
        files = {
            "maven-evidence/report.json": b"{}",
            "maven-evidence/sbom.cdx.json": b"{}",
            "maven-evidence/SHA256SUMS": b"nested list",
            "maven-evidence/第三方告知.md": "原始许可证说明".encode("utf-8"),
            "release-package/LICENSE": b"MIT",
            "release-package/SHA256SUMS": b"nested list",
            "release-package/release-metadata.json": b"{}",
            "release-package/third-party/原文/LICENSE": b"license bytes",
        }
        with (path / "SHA256SUMS").open("a", encoding="utf-8") as manifest:
            for name, data in files.items():
                destination = path / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
                manifest.write(hashlib.sha256(data).hexdigest() + "  " + name + "\n")

    def test_utf8_recursive_producer_evidence_hashes(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            self.evidence_fixture(path)
            checksums.verify(path)
            (path / "maven-evidence/第三方告知.md").write_text("tampered")
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                checksums.verify(path)

    def test_bad_utf8_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            self.fixture(path)
            with (path / "SHA256SUMS").open("ab") as manifest:
                manifest.write(b"\xff")
            with self.assertRaises(UnicodeDecodeError):
                checksums.verify(path)

    def test_evidence_tree_missing_unknown_casefold_symlink_rejected(self):
        for case in ("extra", "unknown-root", "casefold", "symlink", "anchor", "traversal", "ads", "prefix-conflict", "directory-symlink"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp:
                path = Path(temp)
                self.evidence_fixture(path)
                manifest = path / "SHA256SUMS"
                if case in ("extra", "unknown-root", "casefold"):
                    name = {"extra": "maven-evidence/unlisted", "unknown-root": "unknown/第三方.md", "casefold": "maven-evidence/REPORT.json"}[case]
                    destination = path / name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(b"extra")
                    if case != "extra":
                        with manifest.open("a", encoding="utf-8") as output:
                            output.write(hashlib.sha256(b"extra").hexdigest() + "  " + name + "\n")
                elif case == "symlink":
                    (path / "maven-evidence/第三方告知.md").unlink()
                    (path / "maven-evidence/第三方告知.md").symlink_to(path / "LICENSE")
                elif case == "prefix-conflict":
                    with manifest.open("a", encoding="utf-8") as output:
                        output.write(hashlib.sha256(b"x").hexdigest() + "  maven-evidence/report.json/child\n")
                elif case == "directory-symlink":
                    (path / "maven-evidence/linked").symlink_to(path / "release-package", target_is_directory=True)
                elif case == "anchor":
                    target = "maven-evidence/report.json"
                    (path / target).unlink()
                    manifest.write_text("\n".join(line for line in manifest.read_text().splitlines() if not line.endswith("  " + target)) + "\n")
                else:
                    replacement = "maven-evidence/../LICENSE" if case == "traversal" else "maven-evidence/x:ads"
                    manifest.write_text(manifest.read_text().replace("maven-evidence/第三方告知.md", replacement))
                with self.assertRaises(ValueError):
                    checksums.verify(path)

class ReleaseTrust(unittest.TestCase):
    def test_admin_is_only_protected_test_receiver(self):
        import xml.etree.ElementTree as ET
        source = ROOT.parent / "library/src"
        android = "{http://schemas.android.com/apk/res/android}"
        test = ET.parse(source / "androidTest/AndroidManifest.xml").getroot().find("application")
        self.assertEqual(test.attrib[android + "testOnly"], "true")
        receiver = test.find("receiver")
        self.assertEqual(receiver.attrib[android + "name"], "io.peerloom.sdk.TestCertificateAdmin")
        self.assertEqual(receiver.attrib[android + "permission"], "android.permission.BIND_DEVICE_ADMIN")
        for module in (source / "main", ROOT.parent / "sample/src/main"):
            for path in module.rglob("*"):
                if path.is_file():
                    self.assertNotIn(b"TestCertificateAdmin", path.read_bytes())
                    self.assertNotIn(b"BIND_DEVICE_ADMIN", path.read_bytes())

    def test_release_admin_reference_and_binary_sample_rejected(self):
        for binary in (False, True):
            for marker in ("TestCertificateAdmin", "BIND_DEVICE_ADMIN", "android.app.device_admin"):
                with self.subTest(binary=binary, marker=marker), tempfile.TemporaryDirectory() as temp:
                    path = Path(temp) / ("sample-debug.apk" if binary else "library-release.aar")
                    content = ("<manifest>" + marker + "</manifest>")
                    with zipfile.ZipFile(path, "w") as out:
                        out.writestr("AndroidManifest.xml", content.encode("utf-16le") if binary else content.encode())
                    with self.assertRaises(ValueError):
                        artifacts.verify_no_test_trust(path, binary_manifest=binary)

    def test_test_manifest_override_is_not_a_production_override(self):
        import xml.etree.ElementTree as ET
        android = ROOT.parent / "library/src"
        test = ET.parse(android / "androidTest/AndroidManifest.xml").getroot().find("application")
        self.assertEqual(test.attrib["{http://schemas.android.com/tools}replace"], "android:networkSecurityConfig")
        main = (android / "main/AndroidManifest.xml").read_text()
        self.assertNotIn("peerloom_test_", main)
        self.assertNotIn("tools:replace", main)
        self.assertFalse((android / "main/res/raw/peerloom_test_ca.pem").exists())

    def test_release_aar_rejects_test_certificates_and_xml_references(self):
        for bad in (None, "manifest", "resource", "private_key", "xml"):
            with self.subTest(case=bad), tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "library-release.aar"
                with zipfile.ZipFile(path, "w") as out:
                    text = '<manifest><application /></manifest>'
                    if bad == "manifest":
                        text = '<manifest><application test="@xml/peerloom_test_network" /></manifest>'
                    out.writestr("AndroidManifest.xml", text)
                    if bad == "resource":
                        out.writestr("res/raw/peerloom_test_ca.pem", "synthetic test CA")
                    if bad == "private_key":
                        out.writestr("assets/valid.p12", "synthetic test key")
                    if bad == "xml":
                        out.writestr("res/xml/renamed.xml", '<network-security-config test="@raw/peerloom_test_ca"/>')
                if bad is None:
                    artifacts.verify_no_test_trust(path)
                else:
                    with self.assertRaises(ValueError):
                        artifacts.verify_no_test_trust(path)

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
