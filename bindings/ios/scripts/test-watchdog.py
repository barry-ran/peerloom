#!/usr/bin/env python3
# MIT — Copyright (c) 2026 Peerloom contributors.
"""Linux/macOS 真实子进程测试；不是 Swift/XCTest 或 Apple Keychain 验收。"""
import json
import contextlib
import io
import plistlib
import importlib.util
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import xml.etree.ElementTree as ET
from unittest import mock

SCRIPT = Path(__file__).with_name("watchdog.py")
WATCHDOG_SPEC = importlib.util.spec_from_file_location("watchdog", SCRIPT)
WATCHDOG = importlib.util.module_from_spec(WATCHDOG_SPEC)
WATCHDOG_SPEC.loader.exec_module(WATCHDOG)
VERIFY_SPEC = importlib.util.spec_from_file_location("verify_swift", SCRIPT.with_name("verify-swift-tests.py"))
VERIFY = importlib.util.module_from_spec(VERIFY_SPEC)
VERIFY_SPEC.loader.exec_module(VERIFY)
SIGNING_SPEC = importlib.util.spec_from_file_location("inspect_signing", SCRIPT.with_name("inspect-test-signing.py"))
SIGNING = importlib.util.module_from_spec(SIGNING_SPEC)
SIGNING_SPEC.loader.exec_module(SIGNING)


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

    def test_completed_group_kill_and_reap_never_resignals_stale_pgid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sent = []
            original = WATCHDOG.signal_group
            handlers = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
            def reject_redundant_signal(pid, number):
                if sent == [signal.SIGTERM, signal.SIGKILL]:
                    raise PermissionError("synthetic stale PGID after completed cleanup")
                sent.append(number)
                original(pid, number)
            try:
                with mock.patch.object(WATCHDOG, "signal_group", side_effect=reject_redundant_signal), contextlib.redirect_stdout(io.TextIOWrapper(io.BytesIO(), encoding="utf-8")):
                    code = WATCHDOG.run([sys.executable, "-c", "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(100)"],
                                        0.25, 0.05, root / "log", root / "status")
                self.assertEqual(code, 124)
                self.assertEqual(sent, [signal.SIGTERM, signal.SIGKILL])
                self.assertEqual(json.loads((root / "status").read_text())["classification"], "timeout")
            finally:
                for number, handler in handlers.items(): signal.signal(number, handler)

    def test_normal_exited_parent_still_cleans_same_group_with_closed_pipes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); heartbeat = root / "heartbeat"
            child = "import pathlib,signal,time,sys;signal.signal(signal.SIGTERM,signal.SIG_IGN);p=pathlib.Path(sys.argv[1]);\nwhile True:p.write_text(str(time.monotonic()));time.sleep(.02)"
            parent = "import pathlib,subprocess,sys,time;p=pathlib.Path(sys.argv[2]);subprocess.Popen([sys.executable,'-c',sys.argv[1],str(p)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);\nwhile not p.exists():time.sleep(.01)\nprint('child owns closed pipes',flush=True)"
            result = self.execute(root, parent, extra=[child, heartbeat])
            self.assertEqual(result.returncode, 0, result.stderr)
            value = heartbeat.read_bytes(); time.sleep(0.15)
            self.assertEqual(heartbeat.read_bytes(), value, "ordinary leader exit skipped owned group cleanup")

    def test_permission_error_is_not_ignored_for_group_signal(self):
        with mock.patch.object(WATCHDOG.os, "killpg", side_effect=PermissionError("synthetic denied live group")):
            with self.assertRaises(PermissionError): WATCHDOG.signal_group(12345, signal.SIGTERM)

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

    def test_discovery_requires_exact_all_ten_tests(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "discovery"
            names = ["PeerloomSwiftTests." + suite + "/" + method
                     for suite, methods in VERIFY.EXPECTED.items() for method in methods]
            path.write_text("\n".join(names))
            VERIFY.discovery(path)
            for wrong in (names[:-1], names + [names[0]], names + ["OtherTests/testSkipped"]):
                path.write_text("\n".join(wrong))
                with self.assertRaises(ValueError):
                    VERIFY.discovery(path)

    def test_requires_actual_application_host_scheme_not_product_or_guessed_first(self):
        source = SCRIPT.with_name("test-native.sh").read_text()
        validator = source.split("<<'PYSCHEME'\n", 1)[1].split("\nPYSCHEME", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "schemes.json"
            for kind in ("workspace", "project"):
                path.write_text(json.dumps({kind: {"schemes": ["PeerloomSwift", "PeerloomSimulatorHost"]}}))
                self.assertEqual(subprocess.run([sys.executable, "-c", validator, str(path)], capture_output=True).returncode, 0)
            for wrong in ({}, {"workspace": {"schemes": ["PeerloomSwift", "PeerloomStoreProbe"]}},
                          {"workspace": {"schemes": ["Other-Package"]}}):
                path.write_text(json.dumps(wrong))
                self.assertNotEqual(subprocess.run([sys.executable, "-c", validator, str(path)], capture_output=True).returncode, 0)
        self.assertIn("summary['totalTestCount'] >= 13 and summary['failedTests'] == 0", source)
        self.assertIn("CODE_SIGNING_ALLOWED=YES CODE_SIGN_IDENTITY=- DEVELOPMENT_TEAM=", source)
        self.assertIn("run ios-device 600 xcodebuild -scheme PeerloomSwift", source)
        self.assertNotIn("-skip-testing", source)
        self.assertEqual(source.count("    verify_tls"), 2)
        self.assertIn('python3 "$HERE/scripts/verify-tls-evidence.py" "$TLS_DIR/state.json" "$OUT/phase-$PHASE-tls.json"', source)
        verifier = SCRIPT.with_name('verify-tls-evidence.py').read_text()
        self.assertIn("state['rejected_handshakes'] >= 1 and state['accepted_handshakes'] == 0", verifier)

    def test_simulator_id_validation_preserves_exact_case_and_rejects_multiple_ids(self):
        source = SCRIPT.with_name("test-native.sh").read_text()
        validators = re.findall(r"import pathlib,sys,uuid\n.*?(?=\nPY(?:ID)?\n)", source, re.S)
        self.assertEqual(len(validators), 2, "creation and cleanup must both validate the original UUID")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "device-id"
            original = "E3662E63-E85F-4982-B0F4-79F2E786CA4F"
            for validator in validators:
                for value in (original, original.lower()):
                    path.write_text(value + "\n")
                    result = subprocess.run([sys.executable, "-c", validator, str(path)], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, value + "\n")
                for bad in ("invalid", original + "\n" + original, "", original.replace("-", ""), "{" + original + "}"):
                    path.write_text(bad)
                    self.assertNotEqual(subprocess.run([sys.executable, "-c", validator, str(path)], capture_output=True).returncode, 0)

    def test_signing_diagnostics_read_only_bounded_and_redacted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            products, developer = root / "products", root / "developer"
            products.mkdir(); developer.mkdir()
            bundle = products / "fixture.xctest"
            bundle.mkdir()
            (products / "fixture.xctestrun").write_bytes(plistlib.dumps({"TestConfigurations": [
                {"TestTargets": [{"TestBundlePath": "__TESTROOT__/fixture.xctest"}]}]}))
            output = io.StringIO()
            result = subprocess.CompletedProcess([], 1, "", str(bundle.resolve()) + ": code object is not signed at all")
            with mock.patch.object(SIGNING.subprocess, "run", return_value=result) as run, contextlib.redirect_stdout(output):
                SIGNING.inspect(products, developer)
            self.assertEqual(run.call_args.args[0], ["codesign", "-d", "--verbose=2", "--entitlements", ":-", str(bundle.resolve())])
            self.assertEqual(run.call_args.kwargs["timeout"], 10)
            self.assertNotIn(str(root), output.getvalue())
            self.assertIn('"codesign_exit": 1', output.getvalue())
            self.assertNotIn("--sign", str(run.call_args))

    def test_signing_diagnostics_refuse_outside_product_or_developer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            products, developer = root / "products", root / "developer"
            products.mkdir(); developer.mkdir()
            outside = root / "outside"
            outside.mkdir()
            (products / "fixture.xctestrun").write_bytes(plistlib.dumps({"TestHostPath": "__TESTROOT__/../outside"}))
            with mock.patch.object(SIGNING.subprocess, "run") as run, contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(ValueError):
                    SIGNING.inspect(products, developer)
                run.assert_not_called()

    def test_application_host_is_simulator_only_and_reuses_original_tests(self):
        root = SCRIPT.parent.parent / "SimulatorHost"
        project = root / "PeerloomSimulatorHost.xcodeproj/project.pbxproj"
        source = project.read_text()
        definitions = re.findall(r"^        (A[0-9A-F]{23}) = ", source, re.M)
        self.assertEqual(len(definitions), len(set(definitions)))
        references = set(re.findall(r"\bA[0-9A-F]{23}\b", source))
        self.assertEqual(references, set(definitions))
        self.assertIn("SUPPORTED_PLATFORMS = iphonesimulator", source)
        self.assertNotIn("SUPPORTED_PLATFORMS = iphoneos", source)
        self.assertIn('DEVELOPMENT_TEAM = ""', source)
        self.assertNotIn("PROVISIONING_PROFILE", source)
        self.assertIn('CODE_SIGN_IDENTITY = "-"', source)
        self.assertIn('TEST_HOST = "$(BUILT_PRODUCTS_DIR)/PeerloomSimulatorHost.app/PeerloomSimulatorHost"', source)
        for name in ("KeychainTests.swift", "NativeCoreTests.swift"):
            self.assertIn("../SwiftPackage/Tests/PeerloomSwiftTests/" + name, source)
        entitlement = plistlib.loads((root / "SimulatorHost.entitlements").read_bytes())
        self.assertEqual(entitlement, {"keychain-access-groups": ["$(AppIdentifierPrefix)$(PRODUCT_BUNDLE_IDENTIFIER)"]})
        scheme = ET.parse(root / "PeerloomSimulatorHost.xcodeproj/xcshareddata/xcschemes/PeerloomSimulatorHost.xcscheme")
        testables = scheme.findall("./TestAction/Testables/TestableReference")
        self.assertEqual(len(testables), 1)
        self.assertEqual(testables[0].get("skipped"), "NO")
        self.assertEqual(testables[0].find("BuildableReference").get("BlueprintName"), "PeerloomSimulatorTests")
        if sys.platform == "darwin":
            result = subprocess.run(["plutil", "-lint", str(project)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_host_evidence_requires_real_app_path_and_expanded_keychain_group(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            products, developer = root / "Build/Products", root / "developer"
            products.mkdir(parents=True); developer.mkdir()
            app = products / "PeerloomSimulatorHost.app"
            app.mkdir()
            host = app / "PeerloomSimulatorHost"; host.write_bytes(b"synthetic Mach-O placeholder for mock only")
            document = products / "fixture.xctestrun"
            bundle = app / "PlugIns/PeerloomSwiftTests.xctest"; bundle.mkdir(parents=True)
            fields = {"TestBundlePath": "__TESTHOST__/PlugIns/PeerloomSwiftTests.xctest",
                      "TestHostPath": "__TESTROOT__/PeerloomSimulatorHost.app"}
            document.write_bytes(plistlib.dumps({"TestConfigurations": [{"TestTargets": [fields]}]}))
            intermediates = products.parent / "Intermediates.noindex"; intermediates.mkdir()
            entitlement = intermediates / "PeerloomSimulatorHost.app-Simulated.xcent"
            entitlement.write_bytes(plistlib.dumps({"keychain-access-groups": ["io.peerloom.validation.simulatorhost"]}))
            result = subprocess.CompletedProcess([], 0, "", "Signature=adhoc")
            with mock.patch.object(SIGNING.subprocess, "run", return_value=result), contextlib.redirect_stdout(io.StringIO()):
                SIGNING.inspect(products, developer, require_host=True)
                # Actual Xcode app bundle format and historical executable format
                # both resolve only this same target's contained test bundle.
                fields["TestHostPath"] += "/PeerloomSimulatorHost"
                document.write_bytes(plistlib.dumps(fields))
                SIGNING.inspect(products, developer, require_host=True)
                fields["TestBundlePath"] = "__TESTHOST__/../outside.xctest"
                (products / "outside.xctest").mkdir()
                document.write_bytes(plistlib.dumps(fields))
                with self.assertRaisesRegex(ValueError, "绑定"):
                    SIGNING.inspect(products, developer, require_host=True)
                fields["TestBundlePath"] = "__UNKNOWN__/PlugIns/PeerloomSwiftTests.xctest"
                document.write_bytes(plistlib.dumps(fields))
                with self.assertRaisesRegex(ValueError, "占位符"):
                    SIGNING.inspect(products, developer, require_host=True)
                fields["TestBundlePath"] = "__TESTHOST__/PlugIns/PeerloomSwiftTests.xctest"
                document.write_bytes(plistlib.dumps(fields))
                entitlement.write_bytes(plistlib.dumps({"keychain-access-groups": ["$(AppIdentifierPrefix)io.peerloom.validation.simulatorhost"]}))
                with self.assertRaisesRegex(ValueError, "展开"):
                    SIGNING.inspect(products, developer, require_host=True)
                document.write_bytes(plistlib.dumps({"TestBundlePath": "__TESTROOT__/PeerloomSimulatorHost.app/PeerloomSimulatorHost"}))
                with self.assertRaisesRegex(ValueError, "绑定"):
                    SIGNING.inspect(products, developer, require_host=True)

    def test_ios_fast_diagnostic_cannot_replace_full_native_acceptance(self):
        ios = SCRIPT.parent.parent
        workflow = (ios.parent.parent / ".github/workflows/native.yml").read_text()
        build = SCRIPT.with_name("build-ios-diagnostic.sh").read_text()
        self.assertLess(workflow.index("build-ios-diagnostic.sh"), workflow.index("build-xcframework.sh"))
        self.assertIn('"$RUNNER_TEMP/peerloom-ios-diagnostic"', workflow)
        self.assertIn("--stage finalize", workflow)
        self.assertIn("--stage macos-swift", workflow)
        self.assertIn("--stage macos-rust-tls", workflow)
        self.assertIn("--stage ios-device", workflow)
        self.assertEqual(workflow.count("--stage ios-simulator"), 2)
        self.assertIn("if: always()", workflow)
        self.assertIn("peerloom-ios-diagnostic/phase-*.log", workflow)
        self.assertIn("--target aarch64-apple-ios-sim", build)
        self.assertNotIn("lipo", build)
        self.assertIn("assert len(libraries)==1", build)
        self.assertIn('cp -R "$HERE/Sources" "$HERE/Tests"', build)
        self.assertNotIn("-skip-testing", workflow + build)
        native = SCRIPT.with_name("test-native.sh").read_text()
        self.assertIn("inspect-test-signing.py", native)
        self.assertIn("summary['totalTestCount'] >= 13 and summary['failedTests'] == 0", native)

    def runtime_probe(self, root, first=0, second=0, payload=None, second_payload=None, name="out"):
        out = root / name
        out.mkdir()
        valid = json.dumps({"runtimes": [{"identifier": "target-runtime", "isAvailable": True}]}).encode()
        (out / "first-input").write_bytes(valid if payload is None else payload)
        (out / "second-input").write_bytes(valid if second_payload is None else second_payload)
        source = SCRIPT.with_name("test-native.sh").read_text()
        block = source[source.index("    # Environment discovery only:"):source.index("    # New unique simulator only;")]
        stub = '''run_capture() {
  printf '%s\\n' "$*" >> "$RUNNER_TEMP/calls"
  python3 - "$1" "$2" <<'PYMOCK'
import json,os,sys
from pathlib import Path
out=Path(os.environ['OUT'])
first=sys.argv[1]=='ios-runtime-list'
code=int(os.environ['FIRST_CODE'] if first else os.environ['SECOND_CODE'])
(out/('phase-'+sys.argv[1]+'.json')).write_text(json.dumps({'exit_code':code,'timeout_seconds':int(sys.argv[2]),'elapsed_seconds':32.25 if first else 41.5}),encoding='utf-8')
(out/('phase-'+sys.argv[1]+'.stdout')).write_bytes((out/('first-input' if first else 'second-input')).read_bytes())
PYMOCK
  if [[ $1 == ios-runtime-list ]]; then return "$FIRST_CODE"; else return "$SECOND_CODE"; fi
}
'''
        env = dict(os.environ, RUNNER_TEMP=str(root), OUT=str(out), RUNTIME="target-runtime",
                   FIRST_CODE=str(first), SECOND_CODE=str(second))
        result = subprocess.run(["bash", "-euc", stub + block + '\nprintf "SDK-tests-continue\\n"\n'],
                                env=env, capture_output=True, text=True, timeout=5)
        report = json.loads((out / "phase-ios-runtime-readiness.json").read_text(encoding="utf-8"))
        calls = (root / "calls").read_text().splitlines()
        return result, report, calls

    def test_runtime_fast_path_does_not_use_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            result, report, calls = self.runtime_probe(Path(directory))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(calls, ["ios-runtime-list 30 xcrun simctl list runtimes -j"])
            self.assertIn("SDK-tests-continue", result.stdout)
            self.assertFalse(report["recovered"])
            self.assertFalse(report["recovery_attempted"])
            self.assertTrue(report["availability_verified"])
            self.assertEqual(report["fast_path"]["elapsed_seconds"], 32.25)
            self.assertFalse((Path(directory) / "peerloom-simctl-recovery-used").exists())

    def test_runtime_single_recovery_keeps_both_results_and_cumulative_time(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result, report, calls = self.runtime_probe(root, first=124)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(calls, ["ios-runtime-list 30 xcrun simctl list runtimes -j",
                                     "ios-runtime-readiness-recovery 120 xcrun simctl list runtimes -j"])
            self.assertIn("SDK-tests-continue", result.stdout)
            self.assertTrue(report["recovered"])
            self.assertFalse(report["recovery_is_cold_start"])
            self.assertEqual(report["fast_path"]["exit_code"], 124)
            self.assertEqual(report["recovery"], {"exit_code": 0, "timeout_seconds": 120, "elapsed_seconds": 41.5})
            self.assertEqual(report["probe_elapsed_seconds_total"], 73.75)
            self.assertEqual((root / "peerloom-simctl-recovery-used").stat().st_mode & 0o777, 0o600)
            # A later full iOS stage in the SAME job cannot repeat the 120s probe.
            result, report, calls = self.runtime_probe(root, first=124, name="later-stage")
            self.assertEqual(result.returncode, 124, result.stderr)
            self.assertEqual(len(calls), 3)
            self.assertEqual(sum(" 120 " in call for call in calls), 1)
            self.assertFalse(report["recovery_attempted"])
            self.assertNotIn("SDK-tests-continue", result.stdout)

    def test_runtime_failed_recovery_or_cancellation_never_starts_sdk_tests(self):
        for first, second, expected_calls in ((124, 124, 2), (7, 9, 2), (143, 0, 1), (130, 0, 1)):
            with self.subTest(first=first, second=second), tempfile.TemporaryDirectory() as directory:
                result, report, calls = self.runtime_probe(Path(directory), first=first, second=second)
                self.assertEqual(result.returncode, second if expected_calls == 2 else first, result.stderr)
                self.assertEqual(len(calls), expected_calls)
                self.assertFalse(report["recovered"])
                self.assertFalse(report["availability_verified"])
                self.assertNotIn("SDK-tests-continue", result.stdout)

    def test_runtime_json_is_strict_on_fast_and_recovery_paths(self):
        invalid = [b"not-json", b"[]", b'{"runtimes":{}}', b'{"runtimes":[null]}',
                   b'{"runtimes":[]}', b'{"runtimes":[{"identifier":"other","isAvailable":true}]}',
                   b'{"runtimes":[{"identifier":"target-runtime","isAvailable":"true"}]}',
                   b'{"runtimes":[{"identifier":"target-runtime","isAvailable":1}]}',
                   b'{"runtimes":[{"identifier":"target-runtime","isAvailable":false}]}',
                   b'{"runtimes":[{"identifier":"target-runtime","isAvailable":true},{"identifier":"target-runtime","isAvailable":false}]}',
                   b'{"runtimes":[{"identifier":"target-runtime","isAvailable":true,"isAvailable":false}]}',
                   b'{"runtimes":[],"runtimes":[{"identifier":"target-runtime","isAvailable":true}]}',
                   b'{"runtimes":[],"other":NaN}', b'{"runtimes":[],"other":"\xff"}',
                   b' ' * (1024 * 1024) + b'{}']
        for recovered in (False, True):
            for index, payload in enumerate(invalid):
                with self.subTest(recovered=recovered, invalid=index), tempfile.TemporaryDirectory() as directory:
                    result, report, calls = self.runtime_probe(Path(directory), first=124 if recovered else 0,
                                                               payload=None if recovered else payload, second_payload=payload)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertEqual(len(calls), 2 if recovered else 1)
                    self.assertFalse(report["recovered"])
                    self.assertFalse(report["availability_verified"])
                    self.assertEqual(report["classification"], "invalid-probe-evidence")
                    self.assertNotIn("SDK-tests-continue", result.stdout)

    def test_runtime_recovery_marker_never_follows_or_overwrites_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            victim = root / "unrelated"
            victim.write_text("preserve")
            (root / "peerloom-simctl-recovery-used").symlink_to(victim)
            result, report, calls = self.runtime_probe(root, first=124)
            self.assertEqual(result.returncode, 124, result.stderr)
            self.assertEqual(len(calls), 1)
            self.assertFalse(report["recovery_attempted"])
            self.assertEqual(victim.read_text(), "preserve")
            self.assertNotIn("SDK-tests-continue", result.stdout)

    def test_real_ios_runs_before_diagnostics_and_both_fail_closed(self):
        source = SCRIPT.with_name("test-native.sh").read_text()
        block = source[source.index("    test_status=0"):source.index("    run_capture ios-summary")]
        self.assertLess(block.index("run ios-simulator"), block.index("run ios-test-signing"))
        stub = 'run() { echo "$1"; if [[ $1 == ios-simulator ]]; then return "$TEST_CODE"; else return "$SIGN_CODE"; fi; }\n'
        env = dict(os.environ, IOS_PROJECT="fixture", DEVICE="fixture", OUT="fixture", HERE="fixture",
                   DEVELOPER_DIR="fixture", PEERLOOM_TLS_ORIGIN="https://127.0.0.1")
        for test, signing in ((0, 0), (17, 0), (0, 23), (17, 23)):
            result = subprocess.run(["bash", "-euc", stub + block],
                                    env=dict(env, TEST_CODE=str(test), SIGN_CODE=str(signing)),
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, test or signing, result.stderr)
            self.assertIn("ios-simulator\nios-test-signing\n", result.stdout)
            self.assertIn(f"test_exit={test} signing_exit={signing}", result.stdout)

    def test_shell_helpers_preserve_failure_under_or_and_if(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "bin"
            binary.mkdir()
            fake = binary / "python3"
            fake.write_text("#!/bin/sh\nexit 23\n")
            fake.chmod(0o700)
            source = SCRIPT.with_name("test-native.sh").read_text()
            functions = source[source.index("run() {"):source.index("cleanup() {")]
            env = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ["PATH"], HERE=str(root), OUT=str(root))
            for helper in ("run", "run_capture"):
                marker = root / "owned-device-marker"
                marker.write_text("keep on failed cleanup")
                code = functions + '\n' + helper + ' ignored 1 unused || true\n' + \
                    'if ' + helper + ' conditional 1 unused; then rm "$OUT/owned-device-marker"; else printf "status=%s\\n" "$?"; fi\n'
                result = subprocess.run(["bash", "-eu", "-c", code], env=env, capture_output=True, text=True, timeout=3)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("phase passed", result.stdout)
                self.assertIn("status=23", result.stdout)
                self.assertTrue(marker.exists())

    def test_discovery_requires_old_and_new_tests(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "discovery"
            names = sorted("PeerloomSwiftTests." + suite + "/" + method
                           for suite, methods in VERIFY.EXPECTED.items() for method in methods)
            self.assertEqual(len(names), 15)
            self.assertIn("PeerloomSwiftTests.NativeCoreTests/testTypedChildMetadataAndPartialWriteResult", names)
            self.assertIn("PeerloomSwiftTests.NativeCoreTests/testOptionalCapacityDefaultsAndLargeValuesEncodeWithoutClamping", names)
            path.write_text("\n".join(names))
            VERIFY.discovery(path)
            # Every original test, channel test and capacity test remain mandatory.
            for missing in names:
                path.write_text("\n".join(name for name in names if name != missing))
                with self.assertRaises(ValueError, msg=missing):
                    VERIFY.discovery(path)
            path.write_text("\n".join(names + [names[0]]))
            with self.assertRaises(ValueError):
                VERIFY.discovery(path)

    def test_suite_started_or_zero_tests_is_not_success(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "suite"
            methods = VERIFY.EXPECTED["NativeCoreTests"]
            passed = ["Test Case '-[PeerloomSwiftTests.NativeCoreTests " + method + "]' passed (0.001 seconds)."
                      for method in methods]
            path.write_text("\n".join(passed))
            VERIFY.suite_completed("NativeCoreTests", path)
            for wrong in ("Executed 0 tests, with 0 failures", "\n".join(passed).replace("passed", "started"), "\n".join(passed[:-1])):
                path.write_text(wrong)
                with self.assertRaises(ValueError):
                    VERIFY.suite_completed("NativeCoreTests", path)

    def test_aggregate_cannot_hide_a_failed_other_suite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            names = ["PeerloomSwiftTests." + suite + "/" + method
                     for suite, methods in VERIFY.EXPECTED.items() for method in methods]
            (root / "phase-macos-discovery.stdout").write_text("\n".join(names))
            for suite, methods in VERIFY.EXPECTED.items():
                name = "phase-macos-" + suite
                (root / (name + ".log")).write_text("\n".join("Test Case '-[PeerloomSwiftTests." + suite + " " + method + "]' passed (0.01 seconds)." for method in methods))
                (root / (name + ".json")).write_text(json.dumps({"classification": "passed", "exit_code": 0,
                                                               "started_at": "start", "finished_at": "end", "elapsed_seconds": 1}))
            failure = root / "phase-macos-KeychainTests.json"
            success = failure.read_text()
            failure.write_text(json.dumps({"classification": "timeout", "exit_code": 124}))
            with self.assertRaises(ValueError):
                VERIFY.aggregate(root)
            self.assertFalse((root / "phase-macos-swift.json").exists())
            failure.write_text(success)
            VERIFY.aggregate(root)
            self.assertEqual(json.loads((root / "phase-macos-swift.json").read_text())["test_count"], 15)


if __name__ == "__main__":
    unittest.main()
