#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("package_evidence", Path(__file__).with_name("package-third-party.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class EvidenceStatusTests(unittest.TestCase):
    def output(self, directory, status):
        root = Path(directory)
        (root / "report.json").write_text(json.dumps({"evidence_status": status}))
        for name in ("sbom.cdx.json", "第三方告知.md", "SHA256SUMS"):
            (root / name).write_text("fixture")
        return root

    def test_incomplete_stays_explicitly_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.output(directory, "incomplete")
            self.assertEqual(module.write_status(root, 2), "incomplete")
            status = (root / "发布审查状态.txt").read_text()
            self.assertIn("退出码：2", status)
            self.assertIn("法律许可审查：未完成", status)

    def test_collected_is_not_legally_reviewed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.output(directory, "collected-not-legally-reviewed")
            module.write_status(root, 0)
            self.assertIn("不是合规发布批准", (root / "发布审查状态.txt").read_text())

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
