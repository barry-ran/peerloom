#!/usr/bin/env python3
"""离线、可复现的第三方证据清单；不是许可证分类器或法律合规批准。

固定 CycloneDX 1.6，官方 schema: https://github.com/CycloneDX/specification/tree/1.6.1/schema
Cargo.lock: https://doc.rust-lang.org/cargo/guide/cargo-toml-vs-cargo-lock.html
Go MVS/校验: https://go.dev/ref/mod ; https://pkg.go.dev/golang.org/x/mod/sumdb/dirhash
用法: python3 scripts/generate-third-party.py [--output dist/third-party]
先显式下载锁定依赖。脚本不下载、不更新锁文件、不执行上游代码。
输出清单涵盖全部 Cargo.lock 第三方包及 Go MVS 模块（含测试/目标平台候选），
不是某个二进制精确链接清单，不包括容器/操作系统/工具链。缺证据 exit 2。
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tomllib
from urllib.parse import quote, urlparse
import zipfile

SCHEMA = "https://raw.githubusercontent.com/CycloneDX/specification/1.6.1/schema/bom-1.6.schema.json"
SCHEMA_SHA256 = "efc54d749e32a6e16abd19394b80b4c67d846e12c782e04505130375f94ea541"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
MAX_ARCHIVE = 256 << 20
MAX_EXPANDED = 512 << 20
MAX_TEXT = 2 << 20
MAX_EVIDENCE = 64 << 20
MAX_FILES = 100000
LICENSE_NAME = re.compile(r"^(licen[cs]e|copying|copyright|notice|authors)(?:$|[-_.])", re.I)
LICENSE_TEXT_NAME = re.compile(r"^(licen[cs]e|copying)(?:$|[-_.])", re.I)


class EvidenceError(Exception):
    """只包含受控错误码；不泄露子进程 stderr、绝对路径或环境变量。"""


def digest(data):
    return hashlib.sha256(data).hexdigest()


def stream_hash(stream):
    value = hashlib.sha256()
    while chunk := stream.read(1 << 20):
        value.update(chunk)
    return value.hexdigest()


def safe_relative(value):
    if not isinstance(value, str) or not value or "\\" in value or any(ord(c) < 32 for c in value):
        raise EvidenceError("UNSAFE_ARCHIVE_PATH")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or ":" in value:
        raise EvidenceError("UNSAFE_ARCHIVE_PATH")
    return path


def validate_identity(ecosystem, name, version):
    pattern = r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}" if ecosystem == "cargo" else r"[A-Za-z0-9][A-Za-z0-9._~/-]{0,511}"
    if not isinstance(name, str) or not re.fullmatch(pattern, name):
        raise EvidenceError("INVALID_PACKAGE_NAME")
    if any(part in ("", ".", "..") for part in name.split("/")):
        raise EvidenceError("INVALID_PACKAGE_NAME")
    if not isinstance(version, str) or not re.fullmatch(r"v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?", version) or len(version) > 128:
        raise EvidenceError("INVALID_PACKAGE_VERSION")


def package(ecosystem, name, version):
    validate_identity(ecosystem, name, version)
    purl = f"pkg:{'golang' if ecosystem == 'go' else 'cargo'}/{quote(name, safe='/')}@{quote(version, safe='')}"
    return {"ecosystem": ecosystem, "name": name, "version": version, "purl": purl,
            "declared_license": None, "license_classification": "not-performed", "files": [], "issues": []}


def github_repository(value):
    if not isinstance(value, str):
        raise EvidenceError("UNSUPPORTED_UPSTREAM_REPOSITORY")
    parsed = urlparse(value)
    path = parsed.path.removesuffix(".git")
    if parsed.scheme != "https" or parsed.netloc != "github.com" or parsed.query or parsed.fragment or not re.fullmatch(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", path):
        raise EvidenceError("UNSUPPORTED_UPSTREAM_REPOSITORY")
    return "https://github.com" + path


def run(command, cwd):
    env = dict(os.environ, GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local", GOWORK="off", GOFLAGS="")
    try:
        result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise EvidenceError("TOOL_UNAVAILABLE_OR_TIMEOUT") from error
    if result.returncode or len(result.stdout) > (32 << 20):
        raise EvidenceError("TOOL_FAILED_OR_OUTPUT_LIMIT")
    return result.stdout.decode("utf-8")


def json_sequence(data):
    decoder = json.JSONDecoder()
    result = []
    while data.strip():
        value, end = decoder.raw_decode(data.lstrip())
        result.append(value)
        data = data.lstrip()[end:]
    return result


def evidence(record, name, content, blobs):
    safe_relative(name)
    if not content or len(content) > MAX_TEXT:
        raise EvidenceError("EMPTY_OR_OVERSIZE_LICENSE")
    content.decode("utf-8")  # 非文本文件不假称已取得可阅读许可。
    key = digest(content)
    if key not in blobs and sum(map(len, blobs.values())) + len(content) > MAX_EVIDENCE:
        raise EvidenceError("EVIDENCE_LIMIT")
    blobs[key] = content
    record["files"].append({"source_path": name, "sha256": key, "file": f"licenses/{key}.txt"})


def check_members(members, prefix):
    if len(members) > MAX_FILES or sum(size for _, size, _ in members) > MAX_EXPANDED:
        raise EvidenceError("ARCHIVE_RESOURCE_LIMIT")
    names = set()
    for name, _, regular in members:
        path = safe_relative(name)
        if not name.startswith(prefix + "/") or name in names:
            raise EvidenceError("ARCHIVE_PREFIX_OR_DUPLICATE")
        names.add(name)
        if not regular:
            raise EvidenceError("NONREGULAR_ARCHIVE_MEMBER")


def cargo_archive(record, path, expected, blobs):
    if not re.fullmatch(r"[a-f0-9]{64}", expected):
        raise EvidenceError("INVALID_LOCK_CHECKSUM")
    if path.stat().st_size > MAX_ARCHIVE:
        raise EvidenceError("ARCHIVE_RESOURCE_LIMIT")
    with path.open("rb") as source:
        if stream_hash(source) != expected:
            raise EvidenceError("ARCHIVE_CHECKSUM_MISMATCH")
    record["archive_sha256"] = expected
    prefix = f"{record['name']}-{record['version']}"
    with tarfile.open(path, "r:gz") as archive:
        members, expanded = [], 0
        # 逐项限制，不能等 getmembers 完整解压恶意巨型归档之后才检查。
        for member in archive:
            expanded += member.size
            if len(members) >= MAX_FILES or expanded > MAX_EXPANDED:
                raise EvidenceError("ARCHIVE_RESOURCE_LIMIT")
            members.append(member)
        check_members([(m.name, m.size, m.isfile()) for m in members], prefix)
        manifest = archive.getmember(prefix + "/Cargo.toml")
        if not manifest.isfile() or manifest.size > MAX_TEXT:
            raise EvidenceError("INVALID_MANIFEST")
        info = tomllib.loads(archive.extractfile(manifest).read().decode("utf-8"))["package"]
        if (info.get("name"), info.get("version")) != (record["name"], record["version"]):
            raise EvidenceError("MANIFEST_IDENTITY_MISMATCH")
        # 只记录能绑定到已校验 crate 的公开固定提交；不采用 HEAD/tag 推测。
        vcs_name = prefix + "/.cargo_vcs_info.json"
        if vcs_name in archive.getnames():
            vcs_member = archive.getmember(vcs_name)
            if vcs_member.size > MAX_TEXT:
                raise EvidenceError("INVALID_VCS_METADATA")
            vcs = json.loads(archive.extractfile(vcs_member).read())
            commit = vcs.get("git", {}).get("sha1", "")
            path_in_vcs = vcs.get("path_in_vcs", "")
            if re.fullmatch(r"[0-9a-f]{40}", commit) and not vcs.get("git", {}).get("dirty", False):
                try:
                    repository = github_repository(info.get("repository"))
                    if path_in_vcs:
                        safe_relative(path_in_vcs)
                    record["provenance"] = {"repository": repository, "commit": commit, "path_in_vcs": path_in_vcs}
                except EvidenceError:
                    pass  # 未支持的来源不能使用补充证据，但原始归档证据仍有效。
        declared = info.get("license")
        if declared is not None:
            if not isinstance(declared, str) or len(declared) > 512 or not re.fullmatch(r"[A-Za-z0-9 .()+:/_-]+", declared):
                raise EvidenceError("UNSAFE_DECLARED_LICENSE")
            record["declared_license"] = declared  # 原样保留，不推断或选择双许可证分支。
        explicit = info.get("license-file")
        if explicit is not None:
            explicit = str(safe_relative(explicit))
        for item in sorted(members, key=lambda m: m.name):
            relative = item.name[len(prefix) + 1:]
            if LICENSE_NAME.match(PurePosixPath(relative).name) or relative == explicit:
                if not item.isfile() or item.size > MAX_TEXT:
                    raise EvidenceError("NONREGULAR_OR_OVERSIZE_LICENSE")
                evidence(record, relative, archive.extractfile(item).read(MAX_TEXT + 1), blobs)
        if explicit and not any(f["source_path"] == explicit for f in record["files"]):
            record["issues"].append("DECLARED_LICENSE_FILE_MISSING")
        if not any(LICENSE_TEXT_NAME.match(PurePosixPath(f["source_path"]).name) or f["source_path"] == explicit for f in record["files"]):
            record["issues"].append("LICENSE_TEXT_MISSING")


def go_archive(record, path, expected, blobs):
    if not re.fullmatch(r"h1:[A-Za-z0-9+/]{43}=", expected):
        raise EvidenceError("INVALID_GO_SUM")
    if path.stat().st_size > MAX_ARCHIVE:
        raise EvidenceError("ARCHIVE_RESOURCE_LIMIT")
    prefix = f"{record['name']}@{record['version']}"
    with zipfile.ZipFile(path) as archive:
        items = archive.infolist()
        check_members([(m.filename, m.file_size, not m.is_dir() and ((m.external_attr >> 16) & 0o170000) in (0, 0o100000)) for m in items], prefix)
        tree = hashlib.sha256()
        for item in sorted(items, key=lambda m: m.filename):
            with archive.open(item) as source:
                file_hash = stream_hash(source)
            tree.update(f"{file_hash}  {item.filename}\n".encode())
        actual = "h1:" + base64.b64encode(tree.digest()).decode()
        if actual != expected:
            raise EvidenceError("ARCHIVE_CHECKSUM_MISMATCH")
        record["go_sum"] = expected
        for item in sorted(items, key=lambda m: m.filename):
            relative = item.filename[len(prefix) + 1:]
            if LICENSE_NAME.match(PurePosixPath(relative).name):
                if item.file_size > MAX_TEXT:
                    raise EvidenceError("OVERSIZE_LICENSE")
                evidence(record, relative, archive.read(item), blobs)
        if not any(LICENSE_TEXT_NAME.match(PurePosixPath(f["source_path"]).name) for f in record["files"]):
            record["issues"].append("LICENSE_TEXT_MISSING")


def attempt(record, operation):
    try:
        operation()
    except EvidenceError as error:
        record["issues"].append(str(error))
    except (OSError, ValueError, TypeError, KeyError, AttributeError, tarfile.TarError, zipfile.BadZipFile):
        record["issues"].append("ARCHIVE_OR_METADATA_UNREADABLE")


# Explicit reviewed provenance pins: changing a vendor requires a reviewed pin update.
VENDORED = {
    ('nix', '0.31.3'): 'd8b3339019d02a41f5adada077dbe59962fb7a4d29a64de01b0ae853b0cbff72',
    ('rtc', '0.21.1'): '9072d1f2da22f6ea63a8fabccad61c0b18a3494d58b0d20d85533c4475d65b24',
}


def vendor_file(root, relative):
    if not isinstance(relative, str) or any(p in ('', '.', '..') for p in relative.split('/')):
        raise EvidenceError('INVALID_VENDOR_PATH')
    safe_relative(relative)
    path = root
    for part in relative.split('/'):
        path = path / part
        if path.is_symlink():
            raise EvidenceError('VENDOR_SYMLINK')
    if not path.resolve().is_relative_to(root.resolve()) or not path.is_file():
        raise EvidenceError('VENDOR_FILE_MISSING_OR_OUTSIDE')
    if path.stat().st_size > MAX_ARCHIVE:
        raise EvidenceError('VENDOR_FILE_TOO_LARGE')
    return path


def cargo_vendor(record, root, patches, blobs):
    identity = (record['name'], record['version'])
    expected = VENDORED.get(identity)
    if expected is None:
        raise EvidenceError('UNREVIEWED_VENDOR_PATCH')
    name, version = identity
    base = f'third_party/rust/{name}-{version}'
    if patches.get(name) != {'path': '../../' + base + '/crate'}:
        raise EvidenceError('VENDOR_PATCH_PATH_MISMATCH')
    raw = vendor_file(root, base + '/来源.json').read_bytes()
    if digest(raw) != expected:
        raise EvidenceError('VENDOR_PROVENANCE_MISMATCH')
    proof = json.loads(raw)
    if (proof['package']['name'], proof['package']['version']) != identity:
        raise EvidenceError('VENDOR_IDENTITY_MISMATCH')
    patch = proof.get('applied_patch', proof.get('patch'))
    if digest(vendor_file(root, base + '/' + patch['file']).read_bytes()) != patch['sha256']:
        raise EvidenceError('VENDOR_PATCH_CHECKSUM_MISMATCH')
    declared = {}
    license_entries = []
    for item in proof['files']:
        relative = item['path']
        if relative in declared:
            raise EvidenceError('VENDOR_DUPLICATE_PATH')
        content = vendor_file(root, base + '/crate/' + relative).read_bytes()
        if digest(content) != item['sha256']:
            raise EvidenceError('VENDOR_CONTENT_MISMATCH')
        declared[relative] = item['sha256']
        if LICENSE_NAME.match(Path(relative).name):
            if item['sha256'] != item['upstream_sha256']:
                raise EvidenceError('VENDOR_LICENSE_MODIFIED')
            license_entries.append((relative, content))
    crate = root / base / 'crate'
    actual = set()
    for path in crate.rglob('*'):
        if path.is_symlink():
            raise EvidenceError('VENDOR_SYMLINK')
        if path.is_file():
            actual.add(path.relative_to(crate).as_posix())
        elif not path.is_dir():
            raise EvidenceError('VENDOR_SPECIAL_FILE')
    if actual != set(declared):
        raise EvidenceError('VENDOR_UNTRACKED_CONTENT')
    info = tomllib.loads((crate / 'Cargo.toml').read_text(encoding='utf-8'))['package']
    if (info['name'], info['version']) != identity or info.get('license') != proof['package']['declared_license']:
        raise EvidenceError('VENDOR_MANIFEST_MISMATCH')
    if not any(LICENSE_TEXT_NAME.match(Path(relative).name) for relative, _ in license_entries):
        raise EvidenceError('LICENSE_TEXT_MISSING')
    for relative, content in license_entries:
        evidence(record, relative, content, blobs)
    record['declared_license'] = info['license']
    record['vendor_provenance'] = {
        'kind': 'modified-vendored-source', 'path': base + '/crate',
        'manifest_sha256': expected, 'patch_sha256': patch['sha256'],
        'upstream_archive_sha256': proof['archive']['sha256'],
        'upstream_archive_url': proof['archive']['url'],
        'upstream_vcs_commit': proof['archive']['vcs_commit'],
        'excluded_upstream_files': proof.get('excluded', []),
        'inventory_sha256': digest(json.dumps(declared, sort_keys=True, separators=(',', ':')).encode()),
    }
    # Never put the upstream archive hash in modified component.hashes.


def collect(root):
    blobs, records, issues = {}, [], []
    lock = tomllib.loads((root / "src/device-sdk/Cargo.lock").read_text(encoding='utf-8'))
    cargo_manifest = tomllib.loads((root / "src/device-sdk/Cargo.toml").read_text(encoding='utf-8'))
    workspace = cargo_manifest["workspace"]
    patches = cargo_manifest.get("patch", {}).get("crates-io", {})
    local = set()
    for member in workspace["members"]:
        member = safe_relative(member)
        info = tomllib.loads((root / "src/device-sdk" / member / "Cargo.toml").read_text(encoding='utf-8'))["package"]
        version = workspace["package"]["version"] if isinstance(info["version"], dict) else info["version"]
        local.add((info["name"], version))
    cache = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo"))) / "registry/cache"
    for item in lock["package"]:
        if item.get("source") is None and (item["name"], item["version"]) in local:
            continue
        record = package("cargo", item["name"], item["version"])
        records.append(record)
        if item.get("source") is None:
            attempt(record, lambda: cargo_vendor(record, root, patches, blobs))
            continue
        if item.get("source") != REGISTRY:
            record["issues"].append("UNSUPPORTED_NON_CRATES_IO_SOURCE")
            continue
        paths = sorted(cache.glob(f"*/{item['name']}-{item['version']}.crate"))
        if len(paths) != 1:
            record["issues"].append("ARCHIVE_MISSING_OR_AMBIGUOUS")
            continue
        attempt(record, lambda: cargo_archive(record, paths[0], item.get("checksum", ""), blobs))
    go_dir = root / "src/device-server"
    sums = {}
    for line in (go_dir / "go.sum").read_text(encoding='utf-8').splitlines():
        name, version, value = line.split()
        if not version.endswith("/go.mod"):
            sums[(name, version)] = value
    try:
        modules = json_sequence(run(["go", "list", "-mod=readonly", "-m", "-json", "all"], go_dir))
        mod_cache = Path(run(["go", "env", "GOMODCACHE"], go_dir).strip()) / "cache/download"
        for item in modules:
            if item.get("Main"):
                continue
            record = package("go", item["Path"], item.get("Version", ""))
            records.append(record)
            if item.get("Replace"):
                record["issues"].append("UNSUPPORTED_GO_REPLACEMENT")
                continue
            expected = sums.get((record["name"], record["version"]))
            if expected is None:
                record["issues"].append("GO_SUM_MISSING")
                continue
            escape = lambda s: "".join("!" + c.lower() if c.isupper() else c for c in s)
            path = mod_cache / escape(record["name"]) / "@v" / (escape(record["version"]) + ".zip")
            if not path.is_file():
                record["issues"].append("ARCHIVE_MISSING")
                continue
            attempt(record, lambda: go_archive(record, path, expected, blobs))
    except EvidenceError as error:
        issues.append(str(error))
    return records, blobs, issues


def apply_supplement(records, blobs, directory, expected_hash):
    """只读显式固定清单；本函数不联网，清单不是法律审查批准。"""
    if not re.fullmatch(r"[a-f0-9]{64}", expected_hash or ""):
        raise EvidenceError("SUPPLEMENT_MANIFEST_HASH_REQUIRED")
    directory = Path(directory).resolve()
    manifest = directory / "manifest.json"
    if manifest.is_symlink() or manifest.stat().st_size > MAX_TEXT:
        raise EvidenceError("INVALID_SUPPLEMENT_MANIFEST")
    data = manifest.read_bytes()
    if digest(data) != expected_hash:
        raise EvidenceError("SUPPLEMENT_MANIFEST_CHECKSUM_MISMATCH")
    bundle = json.loads(data)
    if bundle.get("format_version") != 1 or len(bundle.get("packages", [])) > 10000:
        raise EvidenceError("INVALID_SUPPLEMENT_MANIFEST")
    by_id = {(r["name"], r["version"]): r for r in records if r["ecosystem"] == "cargo"}
    seen = set()
    for item in bundle["packages"]:
        validate_identity("cargo", item["name"], item["version"])
        identity = (item["name"], item["version"])
        record = by_id.get(identity)
        if identity in seen or record is None:
            raise EvidenceError("SUPPLEMENT_PACKAGE_NOT_LOCKED_OR_DUPLICATE")
        seen.add(identity)
        provenance = {k: item[k] for k in ("repository", "commit", "path_in_vcs")}
        if record.get("archive_sha256") != item["archive_sha256"] or record.get("provenance") != provenance:
            raise EvidenceError("SUPPLEMENT_PROVENANCE_MISMATCH")
        repository = github_repository(item["repository"]).removeprefix("https://github.com/")
        if len(item["files"]) > 256:
            raise EvidenceError("SUPPLEMENT_RESOURCE_LIMIT")
        for proof in item["files"]:
            safe_relative(proof["source_path"])
            sha = proof["sha256"]
            if not re.fullmatch(r"[a-f0-9]{64}", sha) or proof["file"] != f"files/{sha}.txt":
                raise EvidenceError("INVALID_SUPPLEMENT_FILE")
            expected_url = f"https://raw.githubusercontent.com/{repository}/{item['commit']}/{quote(proof['source_path'])}"
            if proof["url"] != expected_url:
                raise EvidenceError("SUPPLEMENT_NOT_PINNED_UPSTREAM")
            path = directory / proof["file"]
            if path.is_symlink() or path.parent.is_symlink() or not path.resolve().is_relative_to(directory) or path.stat().st_size > MAX_TEXT:
                raise EvidenceError("INVALID_SUPPLEMENT_FILE")
            content = path.read_bytes()
            blob_sha = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
            if digest(content) != sha or blob_sha != proof["git_blob_sha1"]:
                raise EvidenceError("SUPPLEMENT_FILE_CHECKSUM_MISMATCH")
            evidence(record, proof["source_path"], content, blobs)
            record["files"][-1].update({"origin": "pinned-upstream-commit", "url": proof["url"], "git_blob_sha1": blob_sha})
        if any(LICENSE_TEXT_NAME.match(PurePosixPath(f["source_path"]).name) or any(p.lower() in ("licenses", "licences") for p in PurePosixPath(f["source_path"]).parts[:-1]) for f in record["files"]):
            record["issues"] = [issue for issue in record["issues"] if issue != "LICENSE_TEXT_MISSING"]


def render(records, blobs, issues, locks, supplement_hash=None):
    records = sorted(records, key=lambda p: p["purl"])
    if len({p["purl"] for p in records}) != len(records):
        raise EvidenceError("DUPLICATE_PACKAGE_IDENTITY")
    for item in records:
        item["files"].sort(key=lambda f: f["source_path"])
        item["issues"].sort()
    incomplete = bool(issues or any(p["issues"] for p in records))
    report = {"format_version": 1, "evidence_status": "incomplete" if incomplete else "collected-not-legally-reviewed",
              "scope": "Cargo.lock third-party packages and Go MVS modules; not binary/container/toolchain inventory",
              "license_classification": "not-performed", "project_license_does_not_relicense_dependencies": True,
              "schema_source": SCHEMA, "schema_sha256": SCHEMA_SHA256,
              "supplement_manifest_sha256": supplement_hash,
              "lock_sha256": locks, "issues": sorted(issues), "packages": records}
    components = []
    for item in records:
        props = [{"name": "peerloom:license-evidence-status", "value": "incomplete" if item["issues"] else "collected-not-legally-reviewed"}]
        if item["declared_license"]:
            props.append({"name": "peerloom:upstream-declared-license", "value": item["declared_license"]})
        for proof in sorted({f["file"] for f in item["files"]}):
            props.append({"name": "peerloom:license-evidence", "value": proof})
        component = {"type": "library", "bom-ref": item["purl"], "purl": item["purl"],
                     "name": item["name"], "version": item["version"], "properties": props}
        if item.get("vendor_provenance"):
            props.append({"name": "peerloom:modified-vendor-provenance", "value": json.dumps(item["vendor_provenance"], sort_keys=True)})
        if item.get("archive_sha256"):
            component["hashes"] = [{"alg": "SHA-256", "content": item["archive_sha256"]}]
        components.append(component)
    bom = {"$schema": SCHEMA, "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
           "components": components, "properties": [{"name": "peerloom:inventory-scope", "value": report["scope"]},
           {"name": "peerloom:evidence-status", "value": report["evidence_status"]}]}
    notice = ["# 第三方许可与告知证据", "", "项目 MIT 许可不覆盖第三方组件。以下为上游原始文本证据，不是法律合规批准。",
              "清单包含锁文件及 Go 模块选择中的开发/测试/平台候选；不是二进制精确链接清单。", "缺失项见 report.json；不得将 incomplete 作为发布合规通过。", ""]
    for item in records:
        notice += [f"## {item['purl']}", "", "上游声明：" + (item["declared_license"] or "未机器声明；未推断分类"), ""]
        notice += [f"- `{f['source_path']}` → [{f['sha256']}]({f['file']})" for f in item["files"]]
        notice += ["缺失/错误：" + ", ".join(item["issues"])] if item["issues"] else []
        notice.append("")
    encode = lambda obj: (json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    files = {"sbom.cdx.json": encode(bom), "report.json": encode(report), "第三方告知.md": "\n".join(notice).encode()}
    files.update({f"licenses/{key}.txt": value for key, value in sorted(blobs.items())})
    files["SHA256SUMS"] = "".join(f"{digest(value)}  {name}\n" for name, value in sorted(files.items())).encode()
    return files, incomplete


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="dist/third-party", help="仓库 dist 内的新目录；拒绝覆盖")
    parser.add_argument("--supplement-dir", help="显式上游提交补充证据目录，默认不使用")
    parser.add_argument("--supplement-sha256", help="补充manifest.json的预先审核SHA256；不能省略或自动信任")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    output = root / args.output
    # 不追随现有输出软链接；拒绝覆盖，避免把旧 complete 结果当成此次结果。
    if output.exists() or output.is_symlink() or not output.resolve().is_relative_to((root / "dist").resolve()) or (root / "dist").is_symlink():
        print("输出必须是仓库 dist 内不存在的新目录", file=sys.stderr)
        return 2
    inputs = ["src/device-sdk/Cargo.toml", "src/device-sdk/Cargo.lock", "src/device-server/go.mod", "src/device-server/go.sum"]
    locks = {name: digest((root / name).read_bytes()) for name in inputs}
    try:
        records, blobs, issues = collect(root)
        if bool(args.supplement_dir) != bool(args.supplement_sha256):
            raise EvidenceError("SUPPLEMENT_DIRECTORY_AND_HASH_REQUIRED")
        if args.supplement_dir:
            apply_supplement(records, blobs, args.supplement_dir, args.supplement_sha256)
        if locks != {name: digest((root / name).read_bytes()) for name in inputs}:
            raise EvidenceError("LOCK_FILES_CHANGED")
        files, incomplete = render(records, blobs, issues, locks, args.supplement_sha256)
        output.mkdir(parents=True)
        for name, content in sorted(files.items()):
            path = output / name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(content)
    except (EvidenceError, OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        code = str(error) if isinstance(error, EvidenceError) else "INPUT_OR_OUTPUT_ERROR"
        print("生成失败：" + code, file=sys.stderr)
        return 2
    print(f"第三方包 {len(records)}；文本 {len(blobs)}；证据{'不完整，见 report.json' if incomplete else '已收集，仍需许可审查'}")
    return 2 if incomplete else 0


if __name__ == "__main__":
    sys.exit(main())
