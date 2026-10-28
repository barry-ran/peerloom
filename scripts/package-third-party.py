#!/usr/bin/env python3
"""为检查产物保留许可证据和缺失状态；绝不将证据缺失改成法律清关通过。"""
import json
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


def main():
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
    if status == "incomplete":
        print("::warning::第三方证据不完整：已保留采集器退出码2及缺失报告；仅构建检查产物，禁止视为发布清关。")
    else:
        print("第三方文本证据已收集；法律许可审查仍未完成。")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError):
        raise SystemExit("第三方证据打包失败；未生成可信检查报告") from None
