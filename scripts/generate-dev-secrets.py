#!/usr/bin/env python3
"""只生成本机开发秘密，不覆盖现有文件；不得用于生产密钥分发。"""
import argparse
import base64
import os
import stat
from pathlib import Path
import secrets
import tempfile


def write_new(directory: Path, name: str, content: str) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".pending-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        # 主机目录 0700；容器只获得显式授权的单文件挂载。
        os.chmod(temporary, 0o444)
        os.link(temporary, directory / name, follow_symlinks=False)
    finally:
        os.unlink(temporary)


def new_replay_key() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii") + "\n"


def add_replay_key(directory: Path) -> None:
    # 显式升级只新增密钥，绝不覆盖已有密钥或数据库密码。
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError(".secrets 必须是现有真实目录")
    if directory.stat().st_uid != os.geteuid():
        raise ValueError(".secrets 必须属于当前用户")
    if stat.S_IMODE(directory.stat().st_mode) != 0o700:
        raise ValueError(".secrets 目录权限必须是 0700")
    write_new(directory, "replay_key", new_replay_key())


def generate(directory: Path) -> None:
    # mkdir 独占创建也会拒绝已有目录、普通文件或符号链接。
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    password = secrets.token_hex(32)
    redis_password = secrets.token_hex(32)
    contents = {
        "replay_key": new_replay_key(),
        "postgres_password": password + "\n",
        "database_url": f"postgres://peerloom:{password}@postgres:5432/peerloom?sslmode=disable\n",
        "redis_password": redis_password + "\n",
        "redis_config": f'bind 0.0.0.0\nprotected-mode yes\nrequirepass {redis_password}\nsave ""\nappendonly no\n',
    }
    for name, content in contents.items():
        write_new(directory, name, content)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--add-replay-key", action="store_true", help="仅为已有开发环境增加不存在的重放加密密钥")
    args = parser.parse_args()
    os.umask(0o077)
    directory = Path(__file__).resolve().parent.parent / ".secrets"
    try:
        if args.add_replay_key:
            add_replay_key(directory)
        else:
            generate(directory)
    except (FileExistsError, ValueError):
        raise SystemExit("拒绝覆盖已有秘密、符号链接或不安全目录；检查现有开发秘密与数据库卷后手工处理。")
    print("已生成本机开发秘密（目录 0700，授权挂载文件 0444）；未输出秘密。")


if __name__ == "__main__":
    main()
