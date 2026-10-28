#!/usr/bin/env python3
"""纯本地归档夹具测试；不下载依赖、不修改仓库锁文件。"""
import base64
import hashlib
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location("third_party", Path(__file__).with_name("generate-third-party.py"))
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)


class ThirdPartyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_cli_status_and_failure_keep_strict_utf8_with_cp1252_streams(self):
        from unittest.mock import patch
        for mode in ('complete','incomplete','error'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                for name in ('src/device-sdk/Cargo.toml','src/device-sdk/Cargo.lock','src/device-server/go.mod','src/device-server/go.sum'):
                    path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'fixed lock')
                out_bytes,err_bytes=io.BytesIO(),io.BytesIO()
                out=io.TextIOWrapper(out_bytes,encoding='cp1252',errors='strict')
                err=io.TextIOWrapper(err_bytes,encoding='cp1252',errors='strict')
                try:
                    with patch.object(gen,'__file__',str(root/'scripts/generate-third-party.py')),patch.object(gen.sys,'argv',['generate-third-party.py']),patch.object(gen.sys,'stdout',out),patch.object(gen.sys,'stderr',err),patch.object(gen,'collect',return_value=([],{},[]),side_effect=gen.EvidenceError('FIXTURE_ERROR') if mode=='error' else None),patch.object(gen,'render',return_value=({'report.json':b'{}'},mode=='incomplete')):
                        code=gen.main()
                    out.flush();err.flush()
                    self.assertEqual(code,0 if mode=='complete' else 2)
                    self.assertIn('生成失败：FIXTURE_ERROR' if mode=='error' else '第三方包 0', (err_bytes if mode=='error' else out_bytes).getvalue().decode('utf-8'))
                    self.assertEqual(out.errors,'strict');self.assertEqual(err.errors,'strict')
                finally:
                    out.detach();err.detach()

    def crate(self, extra=None, manifest=None):
        path = self.root / "sample.crate"
        entries = {"demo-1.2.3/Cargo.toml": manifest or b'[package]\nname="demo"\nversion="1.2.3"\nlicense="MIT OR Apache-2.0"\n',
                   "demo-1.2.3/LICENSE": b"Exact upstream license\r\nCopyright owner\n"}
        entries.update(extra or {})
        with tarfile.open(path, "w:gz") as archive:
            for name, data in entries.items():
                info = tarfile.TarInfo(name)
                if data is None:
                    info.type = tarfile.SYMTYPE
                    info.linkname = "/private/secret"
                    archive.addfile(info)
                else:
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
        return path, gen.digest(path.read_bytes())

    def zip(self, entries):
        path = self.root / "sample.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for name, data in entries.items():
                archive.writestr(name, data)
        lines = b"".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n".encode() for name, data in sorted(entries.items()))
        return path, "h1:" + base64.b64encode(hashlib.sha256(lines).digest()).decode()

    def test_cargo_keeps_exact_bytes_and_uninterpreted_dual_license(self):
        path, checksum = self.crate({"demo-1.2.3/vendor/NOTICE": b"Nested notice\n"})
        item, blobs = gen.package("cargo", "demo", "1.2.3"), {}
        gen.cargo_archive(item, path, checksum, blobs)
        self.assertEqual(item["declared_license"], "MIT OR Apache-2.0")
        self.assertIn(b"Exact upstream license\r\nCopyright owner\n", blobs.values())
        self.assertEqual(len(item["files"]), 2)
        self.assertFalse(item["issues"])

    def test_checksum_rejects_modified_archive(self):
        path, _ = self.crate()
        with self.assertRaisesRegex(gen.EvidenceError, "CHECKSUM"):
            gen.cargo_archive(gen.package("cargo", "demo", "1.2.3"), path, "0" * 64, {})

    def test_tar_traversal_and_nonregular_license_are_rejected(self):
        for name, value in [("demo-1.2.3/../../LICENSE", b"bad"), ("/private/LICENSE", b"bad"), ("demo-1.2.3/LICENSE-link", None)]:
            with self.subTest(name=name):
                path, checksum = self.crate({name: value})
                with self.assertRaises(gen.EvidenceError):
                    gen.cargo_archive(gen.package("cargo", "demo", "1.2.3"), path, checksum, {})

    def test_explicit_license_file_cannot_escape(self):
        path, checksum = self.crate(manifest=b'[package]\nname="demo"\nversion="1.2.3"\nlicense-file="../../private/key"\n')
        with self.assertRaisesRegex(gen.EvidenceError, "UNSAFE"):
            gen.cargo_archive(gen.package("cargo", "demo", "1.2.3"), path, checksum, {})

    def test_manifest_identity_must_match_lock(self):
        path, checksum = self.crate(manifest=b'[package]\nname="other"\nversion="1.2.3"\n')
        with self.assertRaisesRegex(gen.EvidenceError, "IDENTITY"):
            gen.cargo_archive(gen.package("cargo", "demo", "1.2.3"), path, checksum, {})

    def test_go_hash_and_original_notice_without_license_guess(self):
        path, checksum = self.zip({"example.org/demo@v1.2.3/LICENSE": b"An upstream license\n", "example.org/demo@v1.2.3/demo.go": b"package demo\n"})
        item, blobs = gen.package("go", "example.org/demo", "v1.2.3"), {}
        gen.go_archive(item, path, checksum, blobs)
        self.assertIsNone(item["declared_license"])
        self.assertEqual(item["go_sum"], checksum)
        self.assertEqual(list(blobs.values()), [b"An upstream license\n"])
        with self.assertRaisesRegex(gen.EvidenceError, "CHECKSUM"):
            gen.go_archive(item, path, "h1:" + "A" * 43 + "=", {})

    def test_missing_text_is_incomplete_not_silent_success(self):
        path, checksum = self.zip({"example.org/demo@v1.2.3/demo.go": b"package demo\n"})
        item = gen.package("go", "example.org/demo", "v1.2.3")
        gen.go_archive(item, path, checksum, {})
        files, incomplete = gen.render([item], {}, [], {})
        self.assertTrue(incomplete)
        self.assertIn("LICENSE_TEXT_MISSING", item["issues"])
        self.assertEqual(json.loads(files["report.json"])["evidence_status"], "incomplete")

    def test_authors_only_is_not_mistaken_for_license(self):
        path, checksum = self.zip({"example.org/demo@v1.2.3/AUTHORS": b"Contributor\n"})
        item, blobs = gen.package("go", "example.org/demo", "v1.2.3"), {}
        gen.go_archive(item, path, checksum, blobs)
        self.assertTrue(item["files"])
        self.assertIn("LICENSE_TEXT_MISSING", item["issues"])

    def test_nonlicense_symlink_is_rejected_too(self):
        path, checksum = self.crate({"demo-1.2.3/ordinary-link": None})
        with self.assertRaisesRegex(gen.EvidenceError, "NONREGULAR"):
            gen.cargo_archive(gen.package("cargo", "demo", "1.2.3"), path, checksum, {})

    def test_tar_declared_expansion_is_rejected_before_read(self):
        path = self.root / "oversize.crate"
        member = tarfile.TarInfo("demo-1.2.3/oversize")
        member.size = gen.MAX_EXPANDED + 1
        # 写真实 tar 头，故意省略巨量 payload；3.14 addfile 要求非空 fileobj。
        # 生产解析器必须在读取声明内容前拒绝展开量，不能靠构造器提前失败。
        with gzip.open(path, "wb") as archive:
            archive.write(member.tobuf(format=tarfile.USTAR_FORMAT))
            archive.write(b"\0" * 1024)
        self.assertLess(path.stat().st_size, 4096)
        with self.assertRaisesRegex(gen.EvidenceError, "RESOURCE_LIMIT"):
            gen.cargo_archive(gen.package("cargo", "demo", "1.2.3"), path, gen.digest(path.read_bytes()), {})

    def test_zip_symlink_rejected_without_following(self):
        path = self.root / "link.zip"
        with zipfile.ZipFile(path, "w") as archive:
            item = zipfile.ZipInfo("example.org/demo@v1.2.3/LICENSE")
            item.create_system = 3
            item.external_attr = 0o120777 << 16
            archive.writestr(item, "/private/secret")
        with self.assertRaisesRegex(gen.EvidenceError, "NONREGULAR"):
            gen.go_archive(gen.package("go", "example.org/demo", "v1.2.3"), path, "h1:" + "A" * 43 + "=", {})

    def test_go_zip_prefix_and_duplicate_rejected(self):
        path, checksum = self.zip({"../LICENSE": b"secret"})
        with self.assertRaises(gen.EvidenceError):
            gen.go_archive(gen.package("go", "example.org/demo", "v1.2.3"), path, checksum, {})
        with self.assertRaisesRegex(gen.EvidenceError, "DUPLICATE"):
            gen.check_members([("demo/x", 1, True), ("demo/x", 1, True)], "demo")

    def test_bounds_and_invalid_package_identity(self):
        for name, version in [("../secret", "1.2.3"), ("a@token", "1.2.3"), ("demo", "1.2.3\nsecret"), ("/home/private", "1.2.3")]:
            with self.assertRaises(gen.EvidenceError):
                gen.package("cargo", name, version)
        with self.assertRaisesRegex(gen.EvidenceError, "RESOURCE"):
            gen.check_members([("demo/LICENSE", gen.MAX_EXPANDED + 1, True)], "demo")
        with self.assertRaises(gen.EvidenceError):
            gen.evidence(gen.package("cargo", "demo", "1.2.3"), "LICENSE", b"", {})

    def test_reproducible_output_omits_private_paths_and_classification(self):
        path, checksum = self.crate()
        item, blobs = gen.package("cargo", "demo", "1.2.3"), {}
        gen.cargo_archive(item, path, checksum, blobs)
        first, incomplete = gen.render([item], blobs, [], {"Cargo.lock": "a" * 64})
        second, _ = gen.render([item], blobs, [], {"Cargo.lock": "a" * 64})
        self.assertEqual(first, second)
        self.assertFalse(incomplete)
        for value in first.values():
            self.assertNotIn(str(self.root).encode(), value)
            self.assertNotIn(b"manifest_path", value)
        bom = json.loads(first["sbom.cdx.json"])
        self.assertEqual(bom["specVersion"], "1.6")
        self.assertNotIn("licenses", bom["components"][0])
        self.assertIn("not-legally-reviewed", first["report.json"].decode())

    def test_tool_errors_do_not_export_stderr_or_secrets(self):
        with self.assertRaisesRegex(gen.EvidenceError, "TOOL_FAILED") as caught:
            gen.run(["python3", "-c", "import sys;sys.stderr.write('/private/token=SECRET');sys.exit(1)"], self.root)
        self.assertNotIn("SECRET", str(caught.exception))

    def supplemental(self):
        directory = self.root / "supplement"
        (directory / "files").mkdir(parents=True)
        content = b"Exact pinned upstream license\r\n"
        sha = gen.digest(content)
        (directory / "files" / (sha + ".txt")).write_bytes(content)
        provenance = {"repository": "https://github.com/example/demo", "commit": "a" * 40, "path_in_vcs": "crate"}
        item = gen.package("cargo", "demo", "1.2.3")
        item.update({"archive_sha256": "b" * 64, "provenance": provenance, "issues": ["LICENSE_TEXT_MISSING"]})
        proof = {"source_path": "LICENSE", "sha256": sha, "file": f"files/{sha}.txt",
                 "git_blob_sha1": hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest(),
                 "url": "https://raw.githubusercontent.com/example/demo/" + "a" * 40 + "/LICENSE"}
        bundle = {"format_version": 1, "packages": [{"name": "demo", "version": "1.2.3", "archive_sha256": "b" * 64, **provenance, "files": [proof]}]}
        self.save_supplement(directory, bundle)
        return directory, item, bundle, content

    def save_supplement(self, directory, bundle):
        data = json.dumps(bundle).encode()
        (directory / "manifest.json").write_bytes(data)
        return gen.digest(data)

    def test_explicit_supplement_binds_crate_commit_and_exact_text(self):
        directory, item, bundle, content = self.supplemental()
        blobs = {}
        gen.apply_supplement([item], blobs, directory, self.save_supplement(directory, bundle))
        self.assertFalse(item["issues"])
        self.assertEqual(list(blobs.values()), [content])
        self.assertEqual(item["files"][0]["origin"], "pinned-upstream-commit")

    def test_supplement_rejects_unpinned_manifest_and_head_url(self):
        directory, item, bundle, _ = self.supplemental()
        with self.assertRaisesRegex(gen.EvidenceError, "HASH_REQUIRED"):
            gen.apply_supplement([item], {}, directory, None)
        with self.assertRaisesRegex(gen.EvidenceError, "CHECKSUM"):
            gen.apply_supplement([item], {}, directory, "0" * 64)
        bundle["packages"][0]["files"][0]["url"] = "https://raw.githubusercontent.com/example/demo/HEAD/LICENSE"
        with self.assertRaisesRegex(gen.EvidenceError, "NOT_PINNED"):
            gen.apply_supplement([item], {}, directory, self.save_supplement(directory, bundle))

    def test_supplement_rejects_cross_package_commit_or_archive(self):
        directory, item, bundle, _ = self.supplemental()
        for field, value in [("commit", "c" * 40), ("archive_sha256", "c" * 64), ("path_in_vcs", "other")]:
            old = bundle["packages"][0][field]
            bundle["packages"][0][field] = value
            with self.assertRaisesRegex(gen.EvidenceError, "PROVENANCE"):
                gen.apply_supplement([item], {}, directory, self.save_supplement(directory, bundle))
            bundle["packages"][0][field] = old

    def test_supplement_rejects_tampering_and_local_symlink(self):
        directory, item, bundle, _ = self.supplemental()
        proof = bundle["packages"][0]["files"][0]
        path = directory / proof["file"]
        path.write_bytes(b"tampered")
        expected = self.save_supplement(directory, bundle)
        with self.assertRaisesRegex(gen.EvidenceError, "FILE_CHECKSUM"):
            gen.apply_supplement([item], {}, directory, expected)
        path.unlink()
        path.symlink_to(directory / "manifest.json")
        with self.assertRaisesRegex(gen.EvidenceError, "INVALID_SUPPLEMENT_FILE"):
            gen.apply_supplement([item], {}, directory, expected)

    @unittest.skipUnless(os.environ.get("CYCLONEDX_SCHEMA_FILE"), "显式提供固定官方schema才执行；不自动下载")
    def test_official_pinned_cyclonedx_schema(self):
        # jsonschema 复用 scripts/requirements-contracts.txt 已固定的版本。
        from jsonschema import Draft7Validator, FormatChecker
        source = Path(os.environ["CYCLONEDX_SCHEMA_FILE"]).read_bytes()
        self.assertEqual(gen.digest(source), gen.SCHEMA_SHA256)
        item = gen.package("cargo", "demo", "1.2.3")
        item["archive_sha256"] = "a" * 64
        item["declared_license"] = "MIT OR Apache-2.0"
        files, _ = gen.render([item], {}, [], {})
        check = Draft7Validator(json.loads(source), format_checker=FormatChecker())
        check.validate(json.loads(files["sbom.cdx.json"]))
        if os.environ.get("CYCLONEDX_BOM_FILE"):
            check.validate(json.loads(Path(os.environ["CYCLONEDX_BOM_FILE"]).read_bytes()))


if __name__ == "__main__":
    unittest.main()
