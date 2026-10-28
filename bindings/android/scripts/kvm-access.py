#!/usr/bin/env python3
"""Hosted-job-only KVM access: preserve existing access or temporary current-user ACL."""
import os
from pathlib import Path
import stat
import subprocess
import sys

DEVICE = "/dev/kvm"

def command(args):
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE, timeout=10).stdout

def accessible():
    return os.access(DEVICE, os.R_OK | os.W_OK)

def snapshot_path(directory):
    return directory / "peerloom-kvm-original.acl"

def validate_snapshot(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError("invalid ACL snapshot ownership or type")
    content = path.read_text()
    if [line for line in content.splitlines() if line.startswith("# file:")] != ["# file: /dev/kvm"]:
        raise ValueError("ACL snapshot may address only /dev/kvm")

def prepare(directory, run=command, access=accessible):
    path = snapshot_path(directory)
    if path.exists() or path.is_symlink():
        raise ValueError("refuse to replace a previous ACL snapshot")
    if access():
        return
    original = run(["getfacl", "-p", DEVICE])
    # setfacl normally recalculates the shared mask, which could unmask OTHER entries.
    # Preserve it with -n; if its existing rights cannot admit rw, fail instead of
    # broadening any existing user's/group's effective permissions.
    entries = {line.split("::", 1)[0]: line.split("::", 1)[1].split()[0]
               for line in original.splitlines() if line.startswith(("mask::", "group::"))}
    effective_mask = entries.get("mask", entries.get("group", ""))
    if "r" not in effective_mask or "w" not in effective_mask:
        raise PermissionError("KVM ACL mask cannot grant current user rw without widening other access")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as output:
        output.write(original)
    validate_snapshot(path)
    # No chmod, persistent group change, other-user grant, or permissive fallback.
    run(["sudo", "--non-interactive", "setfacl", "-n", "-m", f"u:{os.getuid()}:rw", DEVICE])
    if not access():
        raise PermissionError("current runner still lacks KVM access")

def restore(directory, run=command):
    path = snapshot_path(directory)
    if not path.exists() and not path.is_symlink():
        return
    validate_snapshot(path)
    run(["sudo", "--non-interactive", "setfacl", "--restore=" + str(path)])
    path.unlink()

if __name__ == "__main__":
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("KVM ACL helper is restricted to this ephemeral GitHub Actions job")
    directory = Path(os.environ["RUNNER_TEMP"])
    if sys.argv[1] == "prepare":
        prepare(directory)
    elif sys.argv[1] == "restore":
        restore(directory)
    else:
        raise SystemExit("expected prepare or restore")
