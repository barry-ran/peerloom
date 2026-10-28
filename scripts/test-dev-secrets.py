#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import stat
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("generator", Path(__file__).with_name("generate-dev-secrets.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SecretsTest(unittest.TestCase):
    def test_modes_consistency_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / ".secrets"
            module.generate(directory)
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            password = (directory / "postgres_password").read_text().strip()
            self.assertEqual(len(password), 64)
            self.assertIn(password, (directory / "database_url").read_text())
            for file in directory.iterdir():
                self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o444)
            with self.assertRaises(FileExistsError):
                module.generate(directory)
            self.assertEqual(password, (directory / "postgres_password").read_text().strip())

    def test_reject_symlink(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "target"
            target.mkdir()
            link = Path(root) / ".secrets"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaises(FileExistsError):
                module.generate(link)
            self.assertEqual(list(target.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
