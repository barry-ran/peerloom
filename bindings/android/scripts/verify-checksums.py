#!/usr/bin/env python3
"""Verify the exact Android artifact set before installing or executing anything."""
import hashlib
from pathlib import Path
import re
import sys

FILES = frozenset({"library-release.aar", "library-debug-androidTest.apk", "sample-debug.apk", "device_sdk.h", "LICENSE", "maven-runtime.txt", "maven-test.txt", "cargo-metadata.json"})

EVIDENCE_ROOTS = frozenset({"maven-evidence", "release-package"})

def safe_name(name: str) -> None:
    parts = name.split("/")
    reserved = {"CON", "PRN", "AUX", "NUL", *[f"COM{i}" for i in range(1, 10)], *[f"LPT{i}" for i in range(1, 10)]}
    if (any(p in ("", ".", "..") or p.endswith((" ", ".")) or p.split(".")[0].upper() in reserved for p in parts)
            or "\\" in name or ":" in name or any(ord(c) < 32 or ord(c) == 127 for c in name)):
        raise ValueError("unsafe artifact path")
    if name not in FILES and not (len(parts) > 1 and parts[0] in EVIDENCE_ROOTS):
        raise ValueError("unexpected artifact subtree")

def verify(directory: Path) -> None:
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("artifact root must be an ordinary directory")
    manifest = directory / "SHA256SUMS"
    if manifest.is_symlink() or not manifest.is_file():
        raise ValueError("checksum manifest must be an ordinary file")
    lines = manifest.read_text(encoding="utf-8").splitlines()
    entries = {}
    for line in lines:
        match = re.fullmatch(r"([a-f0-9]{64})  (.+)", line)
        if not match or match[2] in entries:
            raise ValueError("invalid or duplicate checksum entry")
        safe_name(match[2])
        entries[match[2]] = match[1]
    actual = set()
    folded = set()
    for path in directory.rglob("*"):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError("artifact must contain only ordinary files and directories")
        name = path.relative_to(directory).as_posix()
        if name == "SHA256SUMS":
            continue
        key = name.casefold()
        if key in folded:
            raise ValueError("casefold artifact path collision")
        folded.add(key)
        if path.is_dir():
            # Every directory must be in one of the two producer-owned evidence trees.
            safe_name(name + "/directory-marker")
        else:
            safe_name(name)
            actual.add(name)
    if not FILES <= set(entries) or set(entries) != actual:
        raise ValueError("artifact manifest must cover exactly the expected files")
    for prefix in EVIDENCE_ROOTS:
        if (directory / prefix).exists():
            anchors = {"SHA256SUMS", "report.json", "sbom.cdx.json"} if prefix == "maven-evidence" else {"SHA256SUMS", "release-metadata.json", "LICENSE"}
            if not {prefix + "/" + name for name in anchors} <= actual:
                raise ValueError("evidence subtree missing required anchors")
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
