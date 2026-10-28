#!/usr/bin/env python3
"""已批准的精确 Maven 原文缺项披露；不联网、不修改原报告、不作法律判断。"""
import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import xml.etree.ElementTree as ET

COMPLETE = 'collected-not-legally-reviewed'
DOCUMENTED = 'collected_with_documented_gaps_not_legally_reviewed'
INCOMPLETE = 'incomplete'
PINS = json.loads((Path(__file__).resolve().parents[1] / 'release/maven-license-gaps.json').read_text(encoding='utf-8'))
MAX_TEXT = 2 << 20


def classify(report):
    # Full semantic equality also binds scope membership, edges, empty-artifact
    # metadata components, existing complete packages and every available notice.
    # A later graph or genuinely completed report requires a separately reviewed
    # policy update, not a broad "missing LICENSE is fine" escape hatch.
    if report != PINS['expected_report']:
        return INCOMPLETE, []
    canonical = json.dumps(report, sort_keys=True, separators=(',', ':')).encode()
    if hashlib.sha256(canonical).hexdigest() != PINS['source_evidence']['report_sha256']:
        return INCOMPLETE, []
    return DOCUMENTED, copy.deepcopy(PINS['documented_gaps'])


def _text(read_bytes, name, expected):
    path = PurePosixPath(name)
    if path.is_absolute() or '\\' in name or ':' in name or any(part in ('', '.', '..') for part in name.split('/')):
        raise ValueError('UNSAFE_MAVEN_PROOF_PATH')
    data = read_bytes(name)
    if not isinstance(data, bytes) or len(data) > MAX_TEXT:
        raise ValueError('MAVEN_PROOF_SIZE_OR_TYPE')
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('MAVEN_PROOF_BYTES_MISMATCH')
    return data


def _pom_identity(xml):
    def child(node, name):
        matches = [x for x in node if x.tag.split('}')[-1] == name] if node is not None else []
        if len(matches) > 1:
            raise ValueError('DUPLICATE_MAVEN_POM_IDENTITY')
        return matches[0] if matches else None
    if xml.tag.split('}')[-1] != 'project':
        raise ValueError('INVALID_MAVEN_POM_IDENTITY')
    parent = child(xml, 'parent')
    parts = []
    for field in ('groupId', 'artifactId', 'version'):
        item = child(xml, field)
        if item is None and field != 'artifactId':
            item = child(parent, field)
        parts.append((item.text or '').strip() if item is not None else '')
    return ':'.join(parts)


def verify_bound_files(report, read_bytes):
    """Verify actual preserved POM/notice bytes, not absent original JAR/AAR bytes.

    read_bytes receives a relative path inside the already validated Maven proof
    subtree. The caller still owns the complete archive/path/checksum-list checks.
    """
    if classify(report)[0] != DOCUMENTED:
        raise ValueError('UNAPPROVED_MAVEN_GRAPH_OR_GAP')
    for scope in report['scopes']:
        for package in scope['packages']:
            pom = _text(read_bytes, 'poms/' + package['pom_sha256'] + '.xml', package['pom_sha256'])
            if b'<!DOCTYPE' in pom.upper() or b'<!ENTITY' in pom.upper():
                raise ValueError('UNSAFE_MAVEN_POM')
            if _pom_identity(ET.fromstring(pom)) != package['coordinate']:
                raise ValueError('MAVEN_POM_COORDINATE_MISMATCH')
            for notice in package['evidence']:
                _text(read_bytes, notice['file'], notice['sha256'])
