#!/usr/bin/env python3
"""Run real rtc convey regressions with a fixed lock and the reviewed local ICE."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ICE_REGISTRY = b'name = "rtc-ice"\nversion = "0.21.1"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "099984f1be120b2e5692f232f8cbb82e53f6b4261c5c2eeda5be6223ba1adaa9"\n'
ICE_LOCAL = b'name = "rtc-ice"\nversion = "0.21.1"\n'

def validate_lock(original, fixed):
    if original.count(ICE_REGISTRY) != 1:
        raise ValueError("unexpected upstream rtc ICE lock entry")
    if fixed != original.replace(ICE_REGISTRY, ICE_LOCAL):
        raise ValueError("rtc convey lock changes unrelated dependencies")

def main():
    rtc = ROOT / "third_party/rust/rtc-0.21.1/crate"
    ice = ROOT / "third_party/rust/rtc-ice-0.21.1/crate"
    fixed = (ROOT / "scripts/fixtures/rtc-convey.Cargo.lock").read_bytes()
    validate_lock((rtc / "Cargo.lock").read_bytes(), fixed)
    with tempfile.TemporaryDirectory(prefix="peerloom-rtc-convey-") as directory:
        work = Path(directory)
        shutil.copytree(rtc, work / "rtc")
        shutil.copytree(ice, work / "rtc-ice")
        (work / "rtc/Cargo.lock").write_bytes(fixed)
        config = 'patch.crates-io.rtc-ice.path="' + (work / "rtc-ice").as_posix() + '"'
        env = os.environ.copy()
        env.setdefault("CARGO_TARGET_DIR", str(ROOT / "src/device-sdk/target/rtc-convey-tests"))
        return subprocess.run(["cargo", "test", "--manifest-path", str(work / "rtc/Cargo.toml"),
                               "--config", config, "--lib", "--features", "crypto-ring",
                               "--locked", "convey_"], cwd=ROOT, env=env).returncode

if __name__ == "__main__":
    raise SystemExit(main())
