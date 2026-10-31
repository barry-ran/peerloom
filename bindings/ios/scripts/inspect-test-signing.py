#!/usr/bin/env python3
# MIT — Copyright (c) 2026 Peerloom contributors.
"""只读生成的 xctestrun 宿主/测试包签名元数据；不签名、不导入证书、不改权限。"""
import json
from pathlib import Path
import plistlib
import subprocess
import sys


def targets(value):
    if isinstance(value, dict):
        fields = {key: value[key] for key in ("TestHostPath", "TestBundlePath")
                  if isinstance(value.get(key), str)}
        if fields:
            yield fields
        for item in value.values():
            if isinstance(item, (dict, list)):
                yield from targets(item)
    elif isinstance(value, list):
        for item in value:
            yield from targets(item)


def resolve_path(original, products, developer, host=None):
    # Validate placeholders in the generated field, not in trusted directory names.
    unresolved = original.replace("__TESTROOT__", "").replace("__PLATFORMS__", "")
    if host is not None:
        unresolved = unresolved.replace("__TESTHOST__", "")
    if "__" in unresolved:
        raise ValueError("xctestrun 包含未解析的路径占位符")
    expanded = original.replace("__TESTROOT__", str(products)).replace("__PLATFORMS__", str(developer / "Platforms"))
    if host is not None:
        expanded = expanded.replace("__TESTHOST__", str(host))
    target = Path(expanded).resolve(strict=True)
    if not (target.is_relative_to(products) or target.is_relative_to(developer)):
        raise ValueError("拒绝检查本次产物/指定 Xcode 目录以外的文件")
    return target


def inspect(products, developer, require_host=False, test_bundle="PeerloomSwiftTests.xctest"):
    if test_bundle not in ("PeerloomSwiftTests.xctest", "PeerloomServiceTests.xctest"):
        raise ValueError("测试包必须为本仓库明确声明的原生或服务 XCTest target")
    products, developer = products.resolve(strict=True), developer.resolve(strict=True)
    documents = sorted(products.glob("*.xctestrun"))
    if not 1 <= len(documents) <= 16:
        raise ValueError("需要本次 build-for-testing 生成的有界 xctestrun 清单")
    inspected = set()
    host_seen = False
    for document in documents:
        entries = list(targets(plistlib.loads(document.read_bytes())))
        if not entries or len(entries) > 16:
            raise ValueError("xctestrun 未提供宿主/测试包路径或超出诊断界限")
        for fields in entries:
            # Apple's generated app-hosted xctestrun uses a bundle TestHostPath
            # and __TESTHOST__/PlugIns/... for that same target (TN2339).
            host = resolve_path(fields["TestHostPath"], products, developer) if "TestHostPath" in fields else None
            host_bundle = host.parent if host is not None and host.name == "PeerloomSimulatorHost" else host
            resolved = {kind: resolve_path(original, products, developer, host_bundle)
                        for kind, original in fields.items()}
            if require_host and host_bundle is not None:
                expected_executable = host_bundle / "PeerloomSimulatorHost"
                expected_test = host_bundle / "PlugIns" / test_bundle
                if (host_bundle.is_relative_to(products) and host_bundle.name == "PeerloomSimulatorHost.app"
                        and host_bundle.is_dir() and expected_executable.is_file()
                        and expected_executable.resolve(strict=True).parent == host_bundle
                        and resolved.get("TestBundlePath") == expected_test
                        and expected_test.is_dir()):
                    host_seen = True
            for kind, original in fields.items():
                print(json.dumps({"field": kind, "generated_path": original.replace(str(products), "<products>").replace(str(developer), "<developer>")}), flush=True)
                target = resolved[kind]
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
