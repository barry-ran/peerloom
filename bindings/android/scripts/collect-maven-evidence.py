#!/usr/bin/env python3
"""离线 Maven 已解析证据；不下载、不猜许可证、不声称法律清关。"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import xml.etree.ElementTree as ET
import zipfile

MAX_FILE = 256 << 20
MAX_TEXT = 2 << 20
SCOPES = {'releaseRuntimeClasspath', 'debugAndroidTestRuntimeClasspath'}
LICENSE = re.compile(r'^(license|licence|copying|notice|copyright)(?:$|[-_.])', re.I)

class EvidenceError(Exception):
    pass

def sha(data):
    return hashlib.sha256(data).hexdigest()

def checked_file(item, cache):
    path = Path(item['path'])
    if not path.is_absolute() or '..' in path.parts:
        raise EvidenceError('UNSAFE_CACHE_PATH')
    if not path.is_relative_to(cache):
        raise EvidenceError('OUTSIDE_EXPLICIT_CACHE')
    cursor = cache
    if cache.is_symlink() or cache.resolve() != cache:
        raise EvidenceError('CACHE_SYMLINK')
    for part in path.relative_to(cache).parts:
        cursor /= part
        if cursor.is_symlink():
            raise EvidenceError('CACHE_SYMLINK')
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE:
        raise EvidenceError('INVALID_CACHE_FILE')
    data = path.read_bytes()
    if len(data) != item['bytes'] or sha(data) != item['sha256']:
        raise EvidenceError('CACHE_CHECKSUM_MISMATCH')
    return path, data

def license_entries(path, data):
    entries = []
    if path.suffix.lower() not in ('.aar', '.jar', '.zip'):
        return entries
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = set()
        if len(archive.infolist()) > 100000:
            raise EvidenceError('ARCHIVE_ENTRY_LIMIT')
        for item in archive.infolist():
            name = item.filename
            pure = PurePosixPath(name)
            if name in names or pure.is_absolute() or '\\' in name or ':' in name or any(p in ('', '.', '..') for p in name.rstrip('/').split('/')):
                raise EvidenceError('UNSAFE_ARCHIVE_ENTRY')
            names.add(name)
            if stat.S_ISLNK(item.external_attr >> 16):
                raise EvidenceError('ARCHIVE_SYMLINK')
            if LICENSE.match(pure.name) and not item.is_dir():
                if item.file_size > MAX_TEXT:
                    raise EvidenceError('LICENSE_TOO_LARGE')
                entries.append((name, archive.read(item)))
    return entries

def collect(source, cache):
    if source.get('format_version') != 1 or {s['name'] for s in source['scopes']} != SCOPES or len(source['scopes']) != 2:
        raise EvidenceError('REQUIRED_SCOPES_MISSING_OR_DUPLICATE')
    blobs, scopes = {}, []
    for scope in source['scopes']:
        records, identifiers = [], set()
        for item in scope['packages']:
            coordinate = item['coordinate']
            if not re.fullmatch(r'[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+:[A-Za-z0-9_.+-]+', coordinate) or coordinate in identifiers:
                raise EvidenceError('INVALID_OR_DUPLICATE_COORDINATE')
            identifiers.add(coordinate)
            record = {'coordinate': coordinate, 'artifacts': [], 'declared_licenses': [], 'evidence': [], 'issues': list(item['issues'])}
            if item['pom'] is not None:
                path, data = checked_file(item['pom'], cache)
                if len(data) > MAX_TEXT or b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():
                    raise EvidenceError('UNSAFE_POM')
                xml = ET.fromstring(data)
                for licenses in xml:
                    if licenses.tag.split('}')[-1] == 'licenses':
                        for element in licenses:
                            if element.tag.split('}')[-1] == 'license':
                                record['declared_licenses'].append({child.tag.split('}')[-1]: child.text or '' for child in element})
                record['pom_sha256'] = sha(data)
                blobs['poms/' + sha(data) + '.xml'] = data
            else:
                record['issues'].append('POM_MISSING')
            for item_file in item['artifacts']:
                path, data = checked_file(item_file, cache)
                record['artifacts'].append({'name': path.name, 'sha256': sha(data), 'bytes': len(data)})
                for name, text in license_entries(path, data):
                    output = 'licenses/' + sha(text) + '.txt'
                    blobs[output] = text
                    record['evidence'].append({'archive': path.name, 'source_path': name, 'file': output, 'sha256': sha(text)})
            if not any(re.match(r'^(license|licence|copying)(?:$|[-_.])', PurePosixPath(e['source_path']).name, re.I) for e in record['evidence']):
                record['issues'].append('LICENSE_TEXT_MISSING_REVIEWED_SUPPLEMENT_REQUIRED')
            record['issues'] = sorted(set(record['issues']))
            records.append(record)
        for edge in scope['edges']:
            if edge['from'] not in identifiers | {'@root', '@project'} or edge['to'] not in identifiers | {'@project'} or edge['direct'] != (edge['from'] == '@root'):
                raise EvidenceError('INVALID_DEPENDENCY_EDGE')
        scopes.append({'name': scope['name'], 'packages': sorted(records, key=lambda x: x['coordinate']), 'edges': scope['edges']})
    incomplete = any(p['issues'] for s in scopes for p in s['packages'])
    report = {'format_version': 1, 'evidence_status': 'incomplete' if incomplete else 'collected-not-legally-reviewed', 'scope': 'Resolved Maven configurations only; not Cargo/native/toolchain or exact AAR linkage inventory', 'license_classification': 'not-performed', 'scopes': scopes}
    components = {}
    for scope in scopes:
        for record in scope['packages']:
            group, name, version = record['coordinate'].split(':')
            purl = f'pkg:maven/{group}/{name}@{version}'
            component = components.setdefault(purl, {'type': 'library', 'bom-ref': purl, 'purl': purl, 'group': group, 'name': name, 'version': version, 'properties': []})
            component['properties'].append({'name': 'peerloom:maven-configuration', 'value': scope['name']})
            component['properties'].append({'name': 'peerloom:artifact-evidence', 'value': json.dumps(record, sort_keys=True)})
    bom = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1, 'components': [components[k] for k in sorted(components)], 'properties': [{'name': 'peerloom:evidence-status', 'value': report['evidence_status']}]}
    blobs['sbom.cdx.json'] = (json.dumps(bom, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode()
    blobs['report.json'] = (json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode()
    if sum(len(data) for data in blobs.values()) > (64 << 20):
        raise EvidenceError('EVIDENCE_SIZE_LIMIT')
    blobs['SHA256SUMS'] = ''.join(f'{sha(data)}  {name}\n' for name, data in sorted(blobs.items())).encode()
    return blobs, incomplete

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--cache-root', default=os.environ.get('GRADLE_USER_HOME', str(Path.home() / '.gradle')))
    args = parser.parse_args()
    try:
        output = Path(args.output)
        if output.exists() or output.is_symlink() or output.absolute() != output.resolve():
            raise EvidenceError('OUTPUT_MUST_BE_NEW')
        source_path = Path(args.input)
        if source_path.stat().st_size > (16 << 20):
            raise EvidenceError('INPUT_TOO_LARGE')
        blobs, incomplete = collect(json.loads(source_path.read_text()), Path(args.cache_root).absolute())
        output.mkdir(parents=True)
        for name, data in sorted(blobs.items()):
            path = output / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        print('Maven evidence incomplete' if incomplete else 'Maven evidence collected; legal review pending')
        return 2 if incomplete else 0
    except (EvidenceError, OSError, ValueError, KeyError, TypeError, ET.ParseError, zipfile.BadZipFile) as error:
        print(str(error) if isinstance(error, EvidenceError) else 'MAVEN_EVIDENCE_INPUT_ERROR', file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
