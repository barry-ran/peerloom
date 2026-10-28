#!/usr/bin/env python3
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location('evidence', Path(__file__).with_name('collect-maven-evidence.py'))
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)

class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.cache = Path(self.temp.name)
        self.pom = self.file('demo.pom', b'<project><licenses><license><name>MIT</name></license></licenses></project>')
        self.jar = self.archive({'META-INF/LICENSE': b'Original license\r\n'})
        record = {'coordinate': 'org.example:demo:1.2.3', 'pom': self.pom, 'artifacts': [self.jar], 'issues': []}
        self.source = {'format_version': 1, 'scopes': [{'name': name, 'packages': [record.copy()], 'edges': [{'from': '@root', 'to': 'org.example:demo:1.2.3', 'direct': True}]} for name in sorted(gen.SCOPES)]}

    def file(self, name, data):
        path = self.cache / name
        path.write_bytes(data)
        return {'path': str(path), 'bytes': len(data), 'sha256': gen.sha(data)}

    def archive(self, entries):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            for name, data in entries.items(): archive.writestr(name, data)
        return self.file('demo.jar', buffer.getvalue())

    def test_scopes_hashes_and_original_license(self):
        files, incomplete = gen.collect(self.source, self.cache)
        self.assertFalse(incomplete)
        report = json.loads(files['report.json'])
        self.assertEqual(len(report['scopes']), 2)
        self.assertIn(b'Original license\r\n', files.values())
        self.assertEqual(json.loads(files['sbom.cdx.json'])['components'][0]['purl'], 'pkg:maven/org.example/demo@1.2.3')
        self.assertNotIn(str(self.cache).encode(), files['report.json'])

    def test_missing_license_incomplete_not_approved(self):
        item = self.archive({'META-INF/NOTICE': b'Only attribution'})
        for scope in self.source['scopes']: scope['packages'][0]['artifacts'] = [item]
        files, incomplete = gen.collect(self.source, self.cache)
        self.assertTrue(incomplete)
        self.assertIn(b'LICENSE_TEXT_MISSING', files['report.json'])

    def test_hash_tampering(self):
        Path(self.jar['path']).write_bytes(b'changed')
        with self.assertRaisesRegex(gen.EvidenceError, 'CHECKSUM'): gen.collect(self.source, self.cache)

    def test_outside_cache(self):
        self.pom['path'] = '/etc/passwd'
        with self.assertRaisesRegex(gen.EvidenceError, 'OUTSIDE'): gen.collect(self.source, self.cache)

    def test_cache_symlink(self):
        p = Path(self.pom['path']); p.rename(p.with_suffix('.original')); p.symlink_to(p.with_suffix('.original'))
        with self.assertRaisesRegex(gen.EvidenceError, 'SYMLINK'): gen.collect(self.source, self.cache)

    def test_xml_entity_rejected(self):
        self.pom.update(self.file('demo.pom', b'<!DOCTYPE x [<!ENTITY secret SYSTEM "file:///etc/passwd">]><project/>'))
        with self.assertRaisesRegex(gen.EvidenceError, 'UNSAFE_POM'): gen.collect(self.source, self.cache)

    def test_archive_path_rejected(self):
        self.jar.update(self.archive({'../LICENSE': b'bad'}))
        with self.assertRaisesRegex(gen.EvidenceError, 'UNSAFE_ARCHIVE'): gen.collect(self.source, self.cache)

    def test_scope_omission(self):
        self.source['scopes'].pop()
        with self.assertRaisesRegex(gen.EvidenceError, 'SCOPES'): gen.collect(self.source, self.cache)

    def test_graph_unknown_target(self):
        self.source['scopes'][0]['edges'][0]['to'] = 'unknown:package:1'
        with self.assertRaisesRegex(gen.EvidenceError, 'DEPENDENCY_EDGE'): gen.collect(self.source, self.cache)

    def test_missing_pom_incomplete(self):
        for scope in self.source['scopes']: scope['packages'][0]['pom'] = None
        files, incomplete = gen.collect(self.source, self.cache)
        self.assertTrue(incomplete)
        self.assertIn(b'POM_MISSING', files['report.json'])

if __name__ == '__main__': unittest.main()
