#!/usr/bin/env python3
"""Real three-device C ABI fixture: bounded private input, no credential logging."""
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
fixture_path = Path(os.environ["TEST_MULTICONNECTION_FIXTURE_FILE"])
info = fixture_path.lstat()
if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
    raise SystemExit("fixture must be a regular mode-0600 file")
if info.st_size > 65536:
    raise SystemExit("fixture exceeds bounded input")
fixture = json.loads(fixture_path.read_text())
profile = os.environ.get("CARGO_TEST_PROFILE", "dev")
subprocess.run(["cargo", "build", "--profile", profile, "--manifest-path", str(root / "Cargo.toml"), "--locked", "-p", "device-ffi"], check=True)
target = Path(os.environ.get("CARGO_TARGET_DIR", root / "target")).resolve()
lib = target / ("debug" if profile == "dev" else profile)
output = target / "ffi-tests" / "channels"
output.parent.mkdir(parents=True, exist_ok=True)
subprocess.run(["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-pedantic", "-pthread", "-I" + str(root / "device-ffi/include"), str(root / "device-ffi/tests/channels.cpp"), "-L" + str(lib), "-ldevice_ffi", "-Wl,-rpath," + str(lib), "-o", str(output)], check=True)
with tempfile.NamedTemporaryFile(mode="w", prefix="peerloom-c-channels-") as data:
    for role in ("source", "target", "third"):
        device = fixture[role]
        config = dict(abi_version=1, origin=os.environ["TEST_IDENTITY_BASE_URL"], application_id=device["application_id"], storage="external", development_loopback=True, max_connections=2, max_channels_per_connection=4, max_channel_creations_per_connection=8)
        snapshot = dict(revision=1, identity={key: device[key] for key in ("device_id", "device_credential", "expires_at")})
        data.write(json.dumps(config, separators=(",", ":")) + "\n")
        data.write(json.dumps(snapshot, separators=(",", ":")) + "\n")
    for role in ("source", "target", "third"):
        data.write(fixture[role]["device_id"] + "\n")
    data.flush()
    subprocess.run([str(output)], env={**os.environ, "TEST_C_CHANNEL_INPUT": data.name}, timeout=240, check=True)
