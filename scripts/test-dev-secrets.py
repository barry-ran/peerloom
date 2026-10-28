#!/usr/bin/env python3
import base64
import importlib.util
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

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
            self.assertEqual(len(base64.b64decode((directory / "replay_key").read_text().strip(), validate=True)), 32)
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

    def test_key_upgrade_rejects_directory_not_owned_by_current_user(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / ".secrets"
            directory.mkdir(mode=0o700)
            with mock.patch.object(module.os, "geteuid", return_value=directory.stat().st_uid + 1):
                with self.assertRaises(ValueError):
                    module.add_replay_key(directory)
            self.assertEqual(list(directory.iterdir()), [])


    def test_explicit_key_upgrade_is_additive_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / ".secrets"
            directory.mkdir(mode=0o700)
            password = directory / "postgres_password"
            password.write_text("unchanged")
            module.add_replay_key(directory)
            key = (directory / "replay_key").read_bytes()
            self.assertEqual(len(base64.b64decode(key)), 32)
            with self.assertRaises(FileExistsError):
                module.add_replay_key(directory)
            self.assertEqual(key, (directory / "replay_key").read_bytes())
            self.assertEqual(password.read_text(), "unchanged")

    def test_key_upgrade_rejects_symlink_and_insecure_directory(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / "secrets"
            directory.mkdir(mode=0o755)
            with self.assertRaises(ValueError):
                module.add_replay_key(directory)
            link = Path(root) / "link"
            link.symlink_to(directory, target_is_directory=True)
            with self.assertRaises(ValueError):
                module.add_replay_key(link)


if __name__ == "__main__":
    unittest.main()
