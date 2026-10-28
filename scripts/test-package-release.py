#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import tempfile
import tarfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('package', Path(__file__).with_name('package-release.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

producer_spec = importlib.util.spec_from_file_location('producer', Path(__file__).with_name('package-third-party.py'))
producer = importlib.util.module_from_spec(producer_spec)
producer_spec.loader.exec_module(producer)

class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'src/device-sdk').mkdir(parents=True)
        (self.root / 'src/device-sdk/Cargo.toml').write_text('[workspace.package]\nversion="0.1.0"\n')
        (self.root / 'src/device-sdk/Cargo.lock').write_text('lock')
        (self.root / 'LICENSE').write_text('project license')
        (self.root / 'third_party/rust').mkdir(parents=True)
        self.proof = self.root / 'dist/third-party'; self.proof.mkdir(parents=True)
        self.evidence('collected-not-legally-reviewed')
        self.library = self.root / 'release.so'; self.library.write_bytes(b'real-test-fixture-not-binary')
        self.output = self.root / 'package'

    def evidence(self, status):
        record = {'ecosystem': 'cargo', 'name': 'fixture', 'version': '1.0.0', 'archive_sha256': 'a'*64, 'purl': 'pkg:cargo/fixture@1.0.0', 'issues': [] if status == 'collected-not-legally-reviewed' else ['LICENSE_TEXT_MISSING'], 'files': [{'file':'第三方告知.md','source_path':'LICENSE','sha256': m.hashlib.sha256(b'original evidence').hexdigest()}]}
        (self.proof / 'report.json').write_text(json.dumps({'format_version':1, 'issues':[], 'packages':[record], 'evidence_status':status}))
        (self.proof / 'sbom.cdx.json').write_text('{}')
        (self.proof / '第三方告知.md').write_text('original evidence')
        (self.proof / 'SHA256SUMS').write_text(''.join(f'{m.digest(p)}  {p.name}\n' for p in sorted(self.proof.iterdir()) if p.name != 'SHA256SUMS'))

    def finish(self):
        with patch.dict(m.os.environ, {}, clear=True):
            m.finish(self.root, self.output, 'linux-x86_64', 'a'*40, [(self.library, 'sdk/lib/library.so')])

    def test_metadata_and_all_file_checksums(self):
        self.finish()
        metadata = json.loads((self.output / 'release-metadata.json').read_text())
        self.assertEqual(metadata['version'], '0.1.0')
        self.assertEqual(metadata['commit'], 'a'*40)
        self.assertEqual(metadata['build_profile'], 'release')
        self.assertTrue(metadata['release_evidence_complete'])
        entries = (self.output / 'SHA256SUMS').read_text().splitlines()
        names = set()
        for line in entries:
            expected, name = line.split('  ', 1); names.add(name)
            self.assertEqual(m.digest(self.output/name), expected)
        self.assertEqual(names, {str(p.relative_to(self.output)) for p in self.output.rglob('*') if p.is_file()}-{'SHA256SUMS'})

    def test_linux_tar_preserves_executable_and_internal_checksums(self):
        self.library.chmod(0o755)
        self.finish()
        self.assertFalse((self.output/'sdk').exists())
        with tarfile.open(self.output/'peerloom-linux-x86_64.tar.gz', 'r:gz') as archive:
            members = archive.getmembers()
            self.assertTrue(all(m.isfile() and not m.issym() and not m.islnk() for m in members))
            self.assertEqual(archive.getmember('sdk/lib/library.so').mode, 0o755)
            self.assertEqual(archive.getmember('LICENSE').mode, 0o644)
            sums = archive.extractfile('SHA256SUMS').read().decode().splitlines()
            names = set()
            for line in sums:
                expected, name = line.split('  ', 1); names.add(name)
                self.assertEqual(m.hashlib.sha256(archive.extractfile(name).read()).hexdigest(), expected)
            self.assertEqual(names, {member.name for member in members} - {'SHA256SUMS'})

    def test_incomplete_is_not_release_eligible(self):
        self.evidence('incomplete'); self.finish()
        self.assertFalse(json.loads((self.output/'release-metadata.json').read_text())['release_evidence_complete'])

    def test_tampered_report_rejected(self):
        (self.proof/'report.json').write_text('{}')
        with self.assertRaisesRegex(m.PackageError, 'CHECKSUM'): self.finish()

    def test_exact_documented_gap_keeps_original_report_and_incomplete_flag(self):
        (name, version), (checksum, provenance) = next(iter(m.GAPS.KNOWN.items()))
        record = {'ecosystem':'cargo','name':name,'version':version,'purl':f'pkg:cargo/{name}@{version}',
                  'archive_sha256':checksum,'provenance':provenance,'declared_license':'Apache-2.0/MIT',
                  'issues':['LICENSE_TEXT_MISSING'],'files':[]}
        report = {'format_version':1,'evidence_status':'incomplete','issues':[],'packages':[record]}
        raw = json.dumps(report).encode()
        (self.proof/'report.json').write_bytes(raw)
        (self.proof/'SHA256SUMS').write_text(''.join(f'{m.digest(p)}  {p.name}\n' for p in sorted(self.proof.iterdir()) if p.name != 'SHA256SUMS'))
        self.finish()
        meta = json.loads((self.output/'release-metadata.json').read_text())
        self.assertFalse(meta['release_evidence_complete'])
        self.assertTrue(meta['release_delivery_eligible'])
        self.assertEqual(meta['evidence']['cargo_go'], m.GAPS.DOCUMENTED)
        self.assertEqual(meta['documented_gaps'][0]['archive_sha256'], checksum)
        self.assertEqual((self.output/'third-party/cargo-go-all-lock-candidates/report.json').read_bytes(), raw)
        self.assertEqual(meta['legal_review'], 'not-performed')

    def test_symlink_input_rejected(self):
        self.library.unlink(); self.library.symlink_to(self.root/'LICENSE')
        with self.assertRaisesRegex(m.PackageError, 'SYMLINK'): self.finish()

    def test_existing_output_rejected(self):
        self.output.mkdir()
        with self.assertRaisesRegex(m.PackageError, 'OUTPUT'): self.finish()

    def test_unlisted_extra_rejected(self):
        (self.proof/'unreviewed.txt').write_text('not in verified manifest')
        with self.assertRaisesRegex(m.PackageError, 'UNLISTED'): self.finish()

    def test_casefold_duplicate_rejected(self):
        (self.proof/'LICENSE').write_text('first')
        (self.proof/'license').write_text('second')
        self.evidence('collected-not-legally-reviewed')
        observed = {path.name for path in self.proof.iterdir()}
        if {'LICENSE', 'license'} <= observed:
            # Keep the real directory regression on case-sensitive filesystems.
            with self.assertRaisesRegex(m.PackageError, 'CASEFOLD'):
                self.finish()
            (self.proof/'license').unlink()
            self.evidence('collected-not-legally-reviewed')
        # A case-insensitive macOS volume cannot physically retain both entries.
        # Always supply a hostile enumeration too: real checksum reads and the
        # production collision guard are used, with no platform test skip.
        entries = list(self.proof.rglob('*'))
        existing = next(path for path in entries if path.name.casefold() == 'license')
        alias = 'license' if existing.name == 'LICENSE' else 'LICENSE'
        entries.append(self.proof/alias)
        with patch.object(Path, 'rglob', return_value=iter(entries)):
            with self.assertRaisesRegex(m.PackageError, 'CASEFOLD'):
                self.finish()

    def test_reserved_windows_name_rejected(self):
        (self.proof/'CON.txt').write_text('ambiguous')
        self.evidence('collected-not-legally-reviewed')
        with self.assertRaisesRegex(m.PackageError, 'AMBIGUOUS'): self.finish()

    def test_owned_status_is_incrementally_checksummed(self):
        producer.write_status(self.proof, 0)
        producer.append_owned_manifest(self.proof, {'发布审查状态.txt': producer.sha_file(self.proof/'发布审查状态.txt')})
        m.check_evidence(self.proof)

    def test_unknown_extra_cannot_be_sealed_by_producer(self):
        (self.proof/'unknown.txt').write_text('not owned')
        (self.proof/'发布审查状态.txt').write_text('owned')
        with self.assertRaisesRegex(ValueError, 'unlisted'):
            producer.append_owned_manifest(self.proof, {'发布审查状态.txt': producer.sha_file(self.proof/'发布审查状态.txt')})

    def test_producer_does_not_reseal_changed_existing_bytes(self):
        (self.proof/'report.json').write_text('changed')
        with self.assertRaisesRegex(ValueError, 'bytes changed'):
            producer.append_owned_manifest(self.proof, {})

    def test_producer_checks_expected_new_bytes(self):
        (self.proof/'new.txt').write_text('unexpected')
        with self.assertRaisesRegex(ValueError, 'bytes changed'):
            producer.append_owned_manifest(self.proof, {'new.txt': 'a'*64})

    def test_only_declared_build_sources_added(self):
        admin = self.root/'third_party/admin-web-build'; admin.mkdir()
        (admin/'inventory.json').write_text('original inventory')
        (self.root/'src/admin-web').mkdir()
        (self.root/'src/admin-web/package-lock.json').write_text('original lock')
        vendor = self.root/'third_party/rust/nix-0.31.3'; (vendor/'crate').mkdir(parents=True)
        for name in ('crate/LICENSE', '来源.json', '上游补丁.patch', '应用补丁.patch', '回移说明.md'):
            (vendor/name).write_text('original '+name)
        producer.copy_build_notices(self.root, self.proof)
        m.check_evidence(self.proof)
        self.assertEqual((self.proof/'vendor/nix-0.31.3/LICENSE').read_text(), 'original crate/LICENSE')
        with self.assertRaisesRegex(ValueError, 'existing'):
            producer.copy_build_notices(self.root, self.proof)

    def test_wrong_commit_rejected(self):
        with self.assertRaisesRegex(m.PackageError, 'COMMIT'):
            m.finish(self.root,self.output,'linux-x86_64','branch',[])

    def test_nondefault_features_rejected(self):
        with patch.dict(m.os.environ, {'PEERLOOM_CARGO_FEATURES':'diagnostics'}):
            with self.assertRaisesRegex(m.PackageError, 'NONDEFAULT'):
                m.finish(self.root,self.output,'linux-x86_64','a'*40,[])

if __name__ == '__main__': unittest.main()
