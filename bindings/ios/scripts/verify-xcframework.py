#!/usr/bin/env python3
"""验证 Apple 平台分片和规范头一致，不把 plist 检查当作 Mach-O 运行验证。"""
import hashlib
from pathlib import Path
import plistlib
import sys

def verify(root, canonical):
    data = plistlib.loads((root / 'Info.plist').read_bytes())
    expected = {('ios', ''): {'arm64'}, ('ios', 'simulator'): {'arm64', 'x86_64'}, ('macos', ''): {'arm64', 'x86_64'}}
    found = set()
    header_hash = hashlib.sha256(canonical.read_bytes()).digest()
    for library in data['AvailableLibraries']:
        key = (library['SupportedPlatform'], library.get('SupportedPlatformVariant', ''))
        if key in found or key not in expected or set(library['SupportedArchitectures']) != expected[key]:
            raise ValueError('平台/架构重复、缺失或混合')
        found.add(key)
        for field in ['LibraryIdentifier', 'LibraryPath', 'HeadersPath']:
            p = Path(library[field])
            if p.is_absolute() or '..' in p.parts:
                raise ValueError('非法相对路径')
        part = root / library['LibraryIdentifier']
        if not (part / library['LibraryPath']).is_file():
            raise ValueError('缺少原生归档')
        if hashlib.sha256((part / library['HeadersPath'] / 'device_sdk.h').read_bytes()).digest() != header_hash:
            raise ValueError('规范 C 头漂移')
    if found != set(expected):
        raise ValueError('必须包含 macOS、iOS device、iOS simulator 三类分片')

if __name__ == '__main__':
    verify(Path(sys.argv[1]), Path(sys.argv[2]))
    print('XCFramework 平台/头文件结构校验通过（不是设备运行证据）')
