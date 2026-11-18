#!/usr/bin/env python3
"""ELF32/ELF64 verification must reject wrong architectures and broken alignment."""
import importlib.util
from pathlib import Path
import struct
import unittest

spec = importlib.util.spec_from_file_location("artifacts", Path(__file__).with_name("verify-artifacts.py"))
artifacts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifacts)


def elf(abi, alignment=16384):
    cls, machine = artifacts.EXPECTED_ABIS[abi]
    data = bytearray(128)
    data[:6] = b"\x7fELF" + bytes((cls, 1))
    struct.pack_into("<H", data, 18, machine)
    if cls == 1:
        struct.pack_into("<I", data, 28, 64)
        struct.pack_into("<HH", data, 42, 32, 1)
        struct.pack_into("<IIIIIIII", data, 64, 1, 0, 0, 0, 128, 128, 5, alignment)
    else:
        struct.pack_into("<Q", data, 32, 64)
        struct.pack_into("<HH", data, 54, 56, 1)
        struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0, 0, 128, 128, alignment)
    return data


class ElfTest(unittest.TestCase):
    def test_all_abis(self):
        for abi in artifacts.EXPECTED_ABIS:
            with self.subTest(abi=abi):
                artifacts.verify_elf(elf(abi), abi)

    def test_reject_wrong_class_machine_and_alignment(self):
        for abi in artifacts.EXPECTED_ABIS:
            with self.subTest(abi=abi):
                bad_class = elf(abi)
                bad_class[4] = 3
                bad_machine = elf(abi)
                struct.pack_into("<H", bad_machine, 18, 0)
                for data in (bad_class, bad_machine, elf(abi, 4096), elf(abi, 24576), elf(abi)[:80]):
                    with self.assertRaises((AssertionError, struct.error)):
                        artifacts.verify_elf(data, abi)


if __name__ == "__main__":
    unittest.main()
