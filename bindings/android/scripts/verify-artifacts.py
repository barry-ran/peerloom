#!/usr/bin/env python3
"""Verify every shipped ELF LOAD segment, not merely compiler flags."""
import hashlib
from pathlib import Path
import struct
import sys
import zipfile

for archive_name in sys.argv[1:]:
    archive = Path(archive_name)
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
