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


def inspect(products, developer):
    products, developer = products.resolve(strict=True), developer.resolve(strict=True)
    documents = sorted(products.glob("*.xctestrun"))
    if not 1 <= len(documents) <= 16:
        raise ValueError("需要本次 build-for-testing 生成的有界 xctestrun 清单")
    inspected = set()
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
            if target in inspected:
                continue
            inspected.add(target)
            result = subprocess.run(["codesign", "-d", "--verbose=2", "--entitlements", ":-", str(target)],
                                    capture_output=True, text=True, timeout=10, check=False)
            output = (result.stdout + result.stderr).replace(str(products), "<products>").replace(str(developer), "<developer>")
            print(json.dumps({"codesign_exit": result.returncode, "metadata": output[:16384]}), flush=True)
    # An unsigned result is diagnostic evidence, NOT a successful signing acceptance.


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("需要本次 Products 目录与固定 DEVELOPER_DIR")
    inspect(Path(sys.argv[1]), Path(sys.argv[2]))
