#!/usr/bin/env python3
"""有界交付例外，不是法律清关；不修改采集器的原始缺项或原文。"""
import re

COMPLETE = 'collected-not-legally-reviewed'
DOCUMENTED = 'collected_with_documented_gaps_not_legally_reviewed'
INCOMPLETE = 'incomplete'
# Exact registry archives reviewed from the d96 Apple artifact report, not wildcards.
KNOWN = {
    ('crc32c', '0.6.8'): ('3a47af21622d091a8f0fb295b88bc886ac74efcc613efc19f5d0b21de5c89e47',
                        {'repository': 'https://github.com/zowens/crc32c', 'commit': '254a861f7cc71bfe455e86f0e1d86e3c83c33390', 'path_in_vcs': ''}),
    ('r-efi', '6.0.0'): ('f8dcc9c7d52a811697d2151c701e0d08956f92b0e24136cf4cf27b57a6a0d9bf',
                       {'repository': 'https://github.com/r-efi/r-efi', 'commit': '7e1b0322d31d625f81a5656096330934f9cd835d', 'path_in_vcs': ''}),
    ('winapi-i686-pc-windows-gnu', '0.4.0'): ('ac3b87c63620426dd9b991e5ce0329eff545bccbbb34f3be09ff6fb6ab51b7b6', None),
    ('winapi-x86_64-pc-windows-gnu', '0.4.0'): ('712e227841d057c1ee1cd2fb22fa7e5a5461ae8e48fa2ca79ec42cfc1931183f', None),
}

def classify(report):
    """返回交付状态及精确缺项；任何未审缺项保持 incomplete，而非吞异常。"""
    raw = report.get('evidence_status')
    if raw not in (COMPLETE, INCOMPLETE) or report.get('format_version') != 1 or report.get('issues') != []:
        return INCOMPLETE, []
    packages = report.get('packages')
    if not isinstance(packages, list) or not packages:
        return INCOMPLETE, []
    seen, gaps = set(), []
    for package in packages:
        identity = (package.get('ecosystem'), package.get('name'), package.get('version'))
        if identity in seen:
            return INCOMPLETE, []
        seen.add(identity)
        if (identity[0] not in ('cargo', 'go') or not all(isinstance(v, str) and v for v in identity)
                or not isinstance(package.get('files'), list)):
            return INCOMPLETE, []
        if identity[0] == 'cargo':
            source = package.get('archive_sha256')
            vendor = package.get('vendor_provenance', {})
            if not (isinstance(source, str) and re.fullmatch('[0-9a-f]{64}', source)):
                if not (vendor.get('kind') == 'modified-vendored-source' and
                        re.fullmatch('[0-9a-f]{64}', vendor.get('manifest_sha256', '')) and
                        re.fullmatch('[0-9a-f]{64}', vendor.get('inventory_sha256', ''))):
                    return INCOMPLETE, []
        elif not re.fullmatch(r'h1:[A-Za-z0-9+/]{43}=', package.get('go_sum', '')):
            return INCOMPLETE, []
        issues = package.get('issues')
        if not isinstance(issues, list):
            return INCOMPLETE, []
        if identity == ('cargo', 'r-efi', '6.0.0'):
            authors = 'd027e91dbc9cdbb2f1190068e498bd6b61cff022b6a032b191021ba658d96111'
            if not any(f.get('source_path') == 'AUTHORS' and f.get('sha256') == authors and
                       f.get('file') == 'licenses/' + authors + '.txt' for f in package['files']):
                return INCOMPLETE, []
        if not issues:
            if not package['files']:
                return INCOMPLETE, []
            continue
        key = (package.get('name'), package.get('version'))
        known = KNOWN.get(key)
        if (package.get('ecosystem') != 'cargo' or known is None or issues != ['LICENSE_TEXT_MISSING']
                or package.get('archive_sha256') != known[0] or package.get('provenance') != known[1]
                or package.get('purl') != f'pkg:cargo/{key[0]}@{key[1]}'
                or not isinstance(package.get('declared_license'), str) or not package['declared_license']
                or not isinstance(package.get('files'), list)):
            return INCOMPLETE, []
        gaps.append({'ecosystem': 'cargo', 'name': key[0], 'version': key[1],
                     'archive_sha256': known[0], 'reason': 'LICENSE_TEXT_MISSING',
                     'source_url': f'https://static.crates.io/crates/{key[0]}/{key[0]}-{key[1]}.crate',
                     'provenance': known[1], 'declared_license': package['declared_license'],
                     'scope': 'all-lock candidate; actual binary linkage not asserted'})
    if not gaps:
        return (COMPLETE, []) if raw == COMPLETE else (INCOMPLETE, [])
    if raw != INCOMPLETE:
        return INCOMPLETE, []
    return DOCUMENTED, sorted(gaps, key=lambda gap: (gap['name'], gap['version']))
