#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("runner", ROOT / "scripts/run-rtc-convey-tests.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

class LockedConveyTests(unittest.TestCase):
    def test_only_reviewed_ice_registry_to_path_change(self):
        upstream = (ROOT / "third_party/rust/rtc-0.21.1/crate/Cargo.lock").read_bytes()
        fixed = (ROOT / "scripts/fixtures/rtc-convey.Cargo.lock").read_bytes()
        runner.validate_lock(upstream, fixed)
        with self.assertRaises(ValueError):
            runner.validate_lock(upstream, fixed + b"\n")
        with self.assertRaises(ValueError):
            runner.validate_lock(upstream, upstream)
    def test_ci_uses_independent_manifest_and_locked_runner(self):
        ci = (ROOT / "scripts/check.sh").read_text(encoding="utf-8")
        self.assertIn("cargo test --manifest-path ../../third_party/rust/rtc-ice-0.21.1/crate/Cargo.toml --lib --locked", ci)
        self.assertIn("python3 ../../scripts/run-rtc-convey-tests.py", ci)
        self.assertNotIn("cargo test -p rtc-ice --lib", ci)
        self.assertNotIn("cargo test -p rtc --lib", ci)
        self.assertIn("cargo test -p device-transport-webrtc -p webrtc --lib --features webrtc/runtime-mock --locked trickle_park_wake_regression", ci)

if __name__ == "__main__":
    unittest.main()
