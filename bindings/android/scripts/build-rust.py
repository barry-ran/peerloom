#!/usr/bin/env python3
"""Pinned NDK cross-build. Runs only where Android SDK/NDK are already installed (CI)."""
import os
from pathlib import Path
import subprocess
import sys

sdk = Path(sys.argv[1]).resolve()
target = Path(sys.argv[2]).resolve()
android = Path(os.environ.get("ANDROID_SDK_ROOT") or os.environ["ANDROID_HOME"])
ndk = android / "ndk" / "29.0.14206865"
bin_dir = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin"
if not bin_dir.is_dir():
    raise SystemExit("Pinned NDK 29.0.14206865 is required; no implicit download")
for triple, compiler in (("aarch64-linux-android", "aarch64-linux-android24-clang"), ("x86_64-linux-android", "x86_64-linux-android24-clang")):
    subprocess.run(["rustup", "target", "add", "--toolchain", "1.99.1", triple], check=True)
    env = dict(os.environ)
    env["RUSTUP_TOOLCHAIN"] = "1.99.1"
    env["CARGO_BUILD_JOBS"] = "2"
    env["ANDROID_NDK_HOME"] = str(ndk)
    env["ANDROID_NDK_ROOT"] = str(ndk)
    normalized = triple.replace("-", "_")
    env[f"CARGO_TARGET_{normalized.upper()}_LINKER"] = str(bin_dir / compiler)
    env[f"CC_{normalized}"] = str(bin_dir / compiler)
    env[f"CXX_{normalized}"] = str(bin_dir / (compiler + "++"))
    env[f"AR_{normalized}"] = str(bin_dir / "llvm-ar")
    env["CARGO_TARGET_DIR"] = str(target)
    env["CARGO_ENCODED_RUSTFLAGS"] = "-Clink-arg=-Wl,-z,max-page-size=16384"
    subprocess.run(["cargo", "+1.99.1", "build", "--manifest-path", str(sdk / "Cargo.toml"), "--locked", "--release", "--target", triple, "-p", "device-ffi"], env=env, check=True)
