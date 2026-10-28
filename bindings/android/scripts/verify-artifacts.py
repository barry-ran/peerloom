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

if __name__ == "__main__":
    for archive_name in sys.argv[1:]:
        archive = Path(archive_name)
        if archive.suffix == ".aar":
            verify_no_test_trust(archive)
        elif archive.name == "sample-debug.apk":
            verify_no_test_trust(archive, binary_manifest=True)
        count = 0
        with zipfile.ZipFile(archive) as z:
            for item in z.infolist():
                if not item.filename.endswith(".so"):
                    continue
                data = z.read(item)
                assert data[:6] == b"\x7fELF\x02\x01", "expected little-endian ELF64"
                phoff = struct.unpack_from("<Q", data, 32)[0]
                size, length = struct.unpack_from("<HH", data, 54)
                assert size >= 56 and length > 0
                loads = 0
                for index in range(length):
                    header = struct.unpack_from("<IIQQQQQQ", data, phoff + index * size)
                    if header[0] == 1:
                        loads += 1
                        assert header[7] >= 16384, f"unaligned LOAD in {item.filename}"
                        assert header[2] % header[7] == header[3] % header[7]
                assert loads
                count += 1
                print(archive.name, item.filename, "ELF16K", hashlib.sha256(data).hexdigest())
        assert count >= 2, "expected both arm64-v8a and x86_64 native slices"
