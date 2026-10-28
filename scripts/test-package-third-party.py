#!/usr/bin/env python3
import importlib.util
import json
import io
from unittest.mock import patch, Mock
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("package_evidence", Path(__file__).with_name("package-third-party.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class EvidenceStatusTests(unittest.TestCase):
    def output(self, directory, status):
        root = Path(directory)
        (root / "report.json").write_text(json.dumps({"evidence_status": status}), encoding='utf-8')
        for name in ("sbom.cdx.json", "第三方告知.md", "SHA256SUMS"):
            (root / name).write_text("fixture", encoding='utf-8')
        return root

    def test_incomplete_stays_explicitly_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.output(directory, "incomplete")
            self.assertEqual(module.write_status(root, 2), "incomplete")
            status = (root / "发布审查状态.txt").read_text(encoding='utf-8')
            self.assertIn("退出码：2", status)
            self.assertIn("法律许可审查：未完成", status)

    def test_collected_is_not_legally_reviewed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.output(directory, "collected-not-legally-reviewed")
            module.write_status(root, 0)
            self.assertIn("不是合规发布批准", (root / "发布审查状态.txt").read_text(encoding='utf-8'))

    def test_cli_chinese_status_and_error_streams_survive_cp1252(self):
        stdout_bytes, stderr_bytes = io.BytesIO(), io.BytesIO()
        stdout = io.TextIOWrapper(stdout_bytes, encoding='cp1252', errors='strict')
        stderr = io.TextIOWrapper(stderr_bytes, encoding='cp1252', errors='strict')
        try:
            with patch.object(module.sys, 'stdout', stdout), patch.object(module.sys, 'stderr', stderr), \
                 patch.object(module.sys, 'argv', ['package-third-party.py']), \
                 patch.object(module.Path, 'exists', return_value=False), \
                 patch.object(module.Path, 'is_symlink', return_value=False), \
                 patch.object(module.subprocess, 'run', return_value=Mock(returncode=2)), \
                 patch.object(module, 'write_status', return_value='incomplete'), \
                 patch.object(module, 'append_owned_manifest'), \
                 patch.object(module, 'sha_file', return_value='a' * 64):
                module.main()
                print('第三方证据打包失败', file=module.sys.stderr)
            stdout.flush(); stderr.flush()
            self.assertIn('第三方证据不完整', stdout_bytes.getvalue().decode('utf-8'))
            self.assertEqual(stderr_bytes.getvalue().decode('utf-8').strip(), '第三方证据打包失败')
            self.assertEqual(stdout.errors, 'strict')
            self.assertEqual(stderr.errors, 'strict')
        finally:
            stdout.detach(); stderr.detach()

    def test_failed_or_mismatched_collector_never_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.output(directory, "incomplete")
            for code in (0, 1, 3):
                with self.assertRaises(ValueError):
                    module.write_status(root, code)
            (root / "report.json").unlink()
            with self.assertRaises(FileNotFoundError):
                module.write_status(root, 2)


if __name__ == "__main__":
    unittest.main()
