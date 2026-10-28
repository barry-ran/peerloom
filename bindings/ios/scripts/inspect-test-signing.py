#!/usr/bin/env python3
# MIT — Copyright (c) 2026 Peerloom contributors.
"""只读生成的 xctestrun 宿主/测试包签名元数据；不签名、不导入证书、不改权限。"""
import json
from pathlib import Path
import plistlib
import subprocess
import sys


def paths(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in ("TestHostPath", "TestBundlePath") and isinstance(item, str):
                yield key, item
            else:
                yield from paths(item)
    elif isinstance(value, list):
        for item in value:
            yield from paths(item)


def inspect(products, developer, require_host=False):
    products, developer = products.resolve(strict=True), developer.resolve(strict=True)
    documents = sorted(products.glob("*.xctestrun"))
    if not 1 <= len(documents) <= 16:
        raise ValueError("需要本次 build-for-testing 生成的有界 xctestrun 清单")
    inspected = set()
    host_seen = False
    for document in documents:
        entries = list(paths(plistlib.loads(document.read_bytes())))
        if not entries or len(entries) > 32:
            raise ValueError("xctestrun 未提供宿主/测试包路径或超出诊断界限")
        for kind, original in entries:
            print(json.dumps({"field": kind, "generated_path": original.replace(str(products), "<products>").replace(str(developer), "<developer>")}), flush=True)
            expanded = original.replace("__TESTROOT__", str(products)).replace("__PLATFORMS__", str(developer / "Platforms"))
            if "__" in expanded:
                print("signature_status=unresolved-placeholder", flush=True)
                continue
            target = Path(expanded).resolve(strict=True)
            if not (target.is_relative_to(products) or target.is_relative_to(developer)):
                raise ValueError("拒绝检查本次产物/指定 Xcode 目录以外的文件")
            if kind == "TestHostPath" and target.is_relative_to(products) and target.name == "PeerloomSimulatorHost" and target.parent.name == "PeerloomSimulatorHost.app":
                host_seen = True
            if target in inspected:
                continue
            inspected.add(target)
            result = subprocess.run(["codesign", "-d", "--verbose=2", "--entitlements", ":-", str(target)],
                                    capture_output=True, text=True, timeout=10, check=False)
            output = (result.stdout + result.stderr).replace(str(products), "<products>").replace(str(developer), "<developer>")
            print(json.dumps({"codesign_exit": result.returncode, "metadata": output[:16384]}), flush=True)
    if require_host:
        if not host_seen:
            raise ValueError("XCTest 未实际绑定本次 Simulator 应用宿主")
        # Simulator entitlements may be linked into __TEXT,__entitlements rather than
        # the ad-hoc signature. Record Xcode's own expanded packaging inputs as well.
        files = sorted((products.parent / "Intermediates.noindex").glob("**/PeerloomSimulatorHost.app*.xcent"))
        if not 1 <= len(files) <= 16:
            raise ValueError("缺少本次应用宿主的有界 Xcode entitlement 产物")
        group_seen = False
        for path in files:
            if path.stat().st_size > 65536:
                raise ValueError("entitlement 诊断大小越界")
            value = plistlib.loads(path.read_bytes())
            selected = {key: value[key] for key in ("application-identifier", "keychain-access-groups",
                        "com.apple.developer.team-identifier", "get-task-allow", "com.apple.security.get-task-allow") if key in value}
            print(json.dumps({"xcode_entitlements": path.name, "values": selected}), flush=True)
            groups = value.get("keychain-access-groups", [])
            if isinstance(groups, list) and any(isinstance(group, str) and group.endswith("io.peerloom.validation.simulatorhost") and "$(" not in group for group in groups):
                group_seen = True
        if not group_seen:
            raise ValueError("Xcode 未为 Simulator host 展开限定 Keychain group")
    # Simulator metadata is NOT production entitlement/profile or physical-device acceptance.


if __name__ == "__main__":
    if len(sys.argv) not in (3, 4) or (len(sys.argv) == 4 and sys.argv[3] != "--simulator-host"):
        raise SystemExit("需要本次 Products 目录与固定 DEVELOPER_DIR，可追加 --simulator-host")
    inspect(Path(sys.argv[1]), Path(sys.argv[2]), require_host=len(sys.argv) == 4)
