#!/usr/bin/env python3
"""为检查产物保留许可证据和缺失状态；绝不将证据缺失改成法律清关通过。"""
import json
import argparse
import hashlib
import re
import shutil
from pathlib import Path
import subprocess
import sys


def write_status(output, returncode):
    if returncode not in (0, 2):
        raise ValueError("license collector failed")
    report = json.loads((output / "report.json").read_text())
    status = report["evidence_status"]
    if status not in ("incomplete", "collected-not-legally-reviewed"):
        raise ValueError("unknown evidence status")
    if (returncode == 2) != (status == "incomplete"):
        raise ValueError("collector status mismatch")
    for required in ("sbom.cdx.json", "第三方告知.md", "SHA256SUMS"):
        if not (output / required).is_file():
            raise ValueError("missing evidence output")
    (output / "发布审查状态.txt").write_text(
        f"证据状态：{status}\n采集器原始退出码：{returncode}\n"
        "法律许可审查：未完成；本检查产物不是合规发布批准。\n"
        "项目MIT许可不覆盖第三方组件。缺失项与范围限制请阅读report.json及第三方告知.md。\n"
    )
    return status


def sha_file(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def append_owned_manifest(output, owned):
    """仅追加调用方明确拥有的新文件；已有未知文件不能被重新封印。"""
    manifest = output / 'SHA256SUMS'
    known = {}
    for line in manifest.read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if not match:
            raise ValueError('invalid evidence checksum manifest')
        checksum, name = match.groups()
        if name in known or name.startswith('/') or '\\' in name or ':' in name or any(p in ('', '.', '..') for p in name.split('/')):
            raise ValueError('unsafe or duplicate checksum path')
        known[name] = checksum
    if set(known) & set(owned):
        raise ValueError('owned addition would overwrite existing evidence')
    expected = {**known, **owned}
    actual = set()
    for path in output.rglob('*'):
        if path.is_symlink():
            raise ValueError('symlink evidence rejected')
        if path.is_file():
            name = path.relative_to(output).as_posix()
            if name != 'SHA256SUMS':
                actual.add(name)
        elif not path.is_dir():
            raise ValueError('special evidence rejected')
    if actual != set(expected):
        raise ValueError('unlisted or missing evidence file')
    for name, checksum in expected.items():
        if sha_file(output / name) != checksum:
            raise ValueError('evidence bytes changed')
    manifest.write_text(''.join(f'{value}  {name}\n' for name, value in sorted(expected.items())))


def copy_build_notices(root, output):
    # Only these repository-owned producers supply additional build-tool notices.
    sources = {}
    admin = root / 'third_party/admin-web-build'
    if admin.is_symlink() or not admin.is_dir():
        raise ValueError('missing or symlink admin evidence source')
    for path in sorted(admin.rglob('*')):
        if path.is_symlink():
            raise ValueError('symlink admin evidence source')
        if path.is_file():
            sources['admin-web-build/' + path.relative_to(admin).as_posix()] = path
        elif not path.is_dir():
            raise ValueError('special admin evidence source')
    sources['admin-web-build/package-lock.json'] = root / 'src/admin-web/package-lock.json'
    vendor = root / 'third_party/rust/nix-0.31.3'
    for name in ('crate/LICENSE', '来源.json', '上游补丁.patch', '应用补丁.patch', '回移说明.md'):
        sources['vendor/nix-0.31.3/' + Path(name).name] = vendor / name
    owned = {}
    for name, source in sources.items():
        if source.is_symlink() or not source.is_file():
            raise ValueError('missing or symlink declared source')
        target = output / name
        if target.exists() or target.is_symlink():
            raise ValueError('refusing existing notice destination')
        target.parent.mkdir(parents=True, exist_ok=True)
        for parent in target.parents:
            if parent == output:
                break
            if parent.is_symlink():
                raise ValueError('symlink notice destination')
        owned[name] = sha_file(source)
        shutil.copyfile(source, target)
    append_owned_manifest(output, owned)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--include-build-notices', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    output = root / "dist/third-party"
    if output.exists() or output.is_symlink():
        raise ValueError("refusing stale evidence output; choose a clean build workspace")
    # 采集锁文件的全部平台/开发候选，不能把本机已编译子集冒充完整证据。
    subprocess.run(["cargo", "fetch", "--locked"], cwd=root / "src/device-sdk", check=True)
    subprocess.run(["go", "mod", "download", "all"], cwd=root / "src/device-server", check=True)
    result = subprocess.run([sys.executable, str(root / "scripts/generate-third-party.py"),
                             "--output", "dist/third-party",
                             "--supplement-dir", str(root / "third_party/license-evidence"),
                             "--supplement-sha256", "1b21e76395fc7bf1fa41deb6d39e067d19d985cbd3aa7e8ac1342b710473bb71"], cwd=root)
    status = write_status(output, result.returncode)
    append_owned_manifest(output, {"发布审查状态.txt": sha_file(output / "发布审查状态.txt")})
    if args.include_build_notices:
        copy_build_notices(root, output)
    if status == "incomplete":
        print("::warning::第三方证据不完整：已保留采集器退出码2及缺失报告；仅构建检查产物，禁止视为发布清关。")
    else:
        print("第三方文本证据已收集；法律许可审查仍未完成。")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError):
        raise SystemExit("第三方证据打包失败；未生成可信检查报告") from None
