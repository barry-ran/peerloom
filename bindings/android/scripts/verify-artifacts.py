#!/usr/bin/env python3
"""Verify every shipped ELF LOAD segment, not merely compiler flags."""
import hashlib
from pathlib import Path
import struct
import sys
import zipfile

def verify_no_test_trust(archive, binary_manifest=False):
    """Test CA/resources must never leak into the distributable library AAR."""
    with zipfile.ZipFile(archive) as data:
        manifest = data.read("AndroidManifest.xml")
        import xml.etree.ElementTree as ET
        if not binary_manifest:
            ET.fromstring(manifest)  # AAR manifest is XML; unsupported formats fail closed.
        forbidden = ("peerloom_test_", "TestCertificateAdmin", "android.app.device_admin", "BIND_DEVICE_ADMIN")
        for item in data.infolist():
            name = item.filename.lower()
            if "peerloom_test_" in name or name.endswith(".p12"):
                raise ValueError("test trust material in release library")
            if name.endswith(".xml"):
                value = data.read(item)
                if any(marker.encode() in value or marker.encode("utf-16le") in value for marker in forbidden):
                    raise ValueError("test trust reference in release XML")

EXPECTED_ABIS = {"armeabi-v7a": (1, 40), "arm64-v8a": (2, 183), "x86_64": (2, 62)}

def verify_elf(data, abi):
    elf_class, machine = EXPECTED_ABIS[abi]
    assert data[:6] == b"\x7fELF" + bytes((elf_class, 1)), "unexpected ELF class/endianness"
    assert struct.unpack_from("<H", data, 18)[0] == machine, "unexpected ELF machine"
    if elf_class == 1:
        phoff = struct.unpack_from("<I", data, 28)[0]
        size, length = struct.unpack_from("<HH", data, 42)
        fmt, offset_index, address_index, align_index = "<IIIIIIII", 1, 2, 7
    else:
        phoff = struct.unpack_from("<Q", data, 32)[0]
        size, length = struct.unpack_from("<HH", data, 54)
        fmt, offset_index, address_index, align_index = "<IIQQQQQQ", 2, 3, 7
    assert size >= struct.calcsize(fmt) and length > 0
    assert phoff + size * length <= len(data), "truncated program headers"
    loads = 0
    for index in range(length):
        header = struct.unpack_from(fmt, data, phoff + index * size)
        if header[0] == 1:
            loads += 1
            alignment = header[align_index]
            assert alignment >= 16384 and alignment & (alignment - 1) == 0, "unaligned LOAD"
            assert header[offset_index] % alignment == header[address_index] % alignment
    assert loads, "missing LOAD segment"

if __name__ == "__main__":
    for archive_name in sys.argv[1:]:
        archive = Path(archive_name)
        if archive.suffix == ".aar":
            verify_no_test_trust(archive)
        elif archive.name == "sample-debug.apk":
            verify_no_test_trust(archive, binary_manifest=True)
        slices = set()
        with zipfile.ZipFile(archive) as z:
            for item in z.infolist():
                if not item.filename.endswith(".so"):
                    continue
                abi = Path(item.filename).parent.name
                data = z.read(item)
                verify_elf(data, abi)
                if Path(item.filename).name == "libpeerloom_android.so":
                    slices.add(abi)
                print(archive.name, item.filename, "ELF16K", hashlib.sha256(data).hexdigest())
        assert slices == set(EXPECTED_ABIS), "expected all three Peerloom native slices"
