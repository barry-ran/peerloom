#!/usr/bin/env python3
"""Verify the exact Android artifact set before installing or executing anything."""
import hashlib
from pathlib import Path
import re
import sys

FILES = frozenset({"library-release.aar", "library-debug-androidTest.apk", "sample-debug.apk", "device_sdk.h", "LICENSE", "maven-runtime.txt", "maven-test.txt", "cargo-metadata.json"})

def verify(directory: Path) -> None:
    manifest = directory / "SHA256SUMS"
    if manifest.is_symlink() or not manifest.is_file():
        raise ValueError("checksum manifest must be an ordinary file")
    lines = manifest.read_text(encoding="ascii").splitlines()
    entries = {}
    for line in lines:
        match = re.fullmatch(r"([a-f0-9]{64})  ([A-Za-z0-9_.-]+)", line)
        if not match or match[2] in entries:
            raise ValueError("invalid or duplicate checksum entry")
        entries[match[2]] = match[1]
    actual = {p.name for p in directory.iterdir()}
    if set(entries) != FILES or actual != FILES | {"SHA256SUMS"}:
        raise ValueError("artifact manifest must cover exactly the expected files")
    for name, digest in entries.items():
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("artifact must be an ordinary file")
        hasher = hashlib.sha256()
        with path.open("rb") as data:
            for chunk in iter(lambda: data.read(1024 * 1024), b""):
                hasher.update(chunk)
        if hasher.hexdigest() != digest:
            raise ValueError("artifact checksum mismatch")

if __name__ == "__main__":
    verify(Path(sys.argv[1]))
    print("Android artifact checksums: exact set verified")
