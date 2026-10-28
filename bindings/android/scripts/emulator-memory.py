#!/usr/bin/env python3
"""Read-only resource admission for the job-owned 4096 MiB CI AVD."""
from pathlib import Path


def validate(text):
    values = {}
    for line in text.splitlines():
        fields = line.split()
        if fields and fields[0] in ("MemTotal:", "MemAvailable:"):
            if len(fields) != 3 or fields[2] != "kB" or not fields[1].isdigit():
                raise ValueError("invalid host memory counters")
            if fields[0] in values:
                raise ValueError("duplicate host memory counter")
            values[fields[0]] = int(fields[1]) // 1024
    total, available = values.get("MemTotal:", 0), values.get("MemAvailable:", 0)
    if not 6144 <= available <= total:
        raise ValueError("owned 4096 MiB AVD requires at least 6144 MiB host available RAM")
    return total, available


if __name__ == "__main__":
    total, available = validate(Path("/proc/meminfo").read_text())
    print(f"CI host RAM MiB total={total} available={available}; owned AVD RAM MiB=4096", flush=True)
