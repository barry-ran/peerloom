#!/usr/bin/env python3
"""真实 C 服务集成；只读 0600 fixture，临时 0600 输入，绝不输出凭证。"""
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
fixture_path = Path(os.environ["TEST_SIGNAL_FIXTURE_FILE"])
if stat.S_IMODE(fixture_path.stat().st_mode) != 0o600:
    raise SystemExit("fixture must be mode 0600")
fixture = json.loads(fixture_path.read_text())
origin = os.environ["TEST_IDENTITY_BASE_URL"]
subprocess.run(["cargo", "build", "--manifest-path", str(root / "Cargo.toml"), "--locked", "-p", "device-ffi"], check=True)
target = Path(os.environ.get("CARGO_TARGET_DIR", root / "target")).resolve()
output = target / "ffi-tests" / "service"
output.parent.mkdir(parents=True, exist_ok=True)
subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-pthread", "-I" + str(root / "device-ffi/include"), str(root / "device-ffi/tests/service.c"), "-L" + str(target / "debug"), "-ldevice_ffi", "-Wl,-rpath," + str(target / "debug"), "-o", str(output)], check=True)
with tempfile.NamedTemporaryFile(mode="w", prefix="peerloom-c-pair-", delete=True) as data:
    for role in ("source", "target"):
        device = fixture[role]
        config = dict(abi_version=1, origin=origin, application_id=device["application_id"], storage="external", development_loopback=True)
        snapshot = dict(revision=1, identity={key: device[key] for key in ("device_id", "device_credential", "expires_at")})
        data.write(json.dumps(config, separators=(",", ":")) + "\n")
        data.write(json.dumps(snapshot, separators=(",", ":")) + "\n")
    data.write(fixture["target"]["device_id"] + "\n")
    data.flush()
    subprocess.run([str(output)], env={**os.environ, "TEST_C_PAIR_INPUT": data.name}, timeout=180, check=True)
