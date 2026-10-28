#!/usr/bin/env python3
"""只生成本机开发秘密，不覆盖现有文件；不得用于生产密钥分发。"""
import os
from pathlib import Path
import secrets
import tempfile


def generate(directory: Path) -> None:
    # mkdir 独占创建也会拒绝已有目录、普通文件或符号链接。
    directory.mkdir(mode=0o700)
    os.chmod(directory, 0o700)
    password = secrets.token_hex(32)
    redis_password = secrets.token_hex(32)
    contents = {
        "postgres_password": password + "\n",
        "database_url": f"postgres://peerloom:{password}@postgres:5432/peerloom?sslmode=disable\n",
        "redis_password": redis_password + "\n",
        "redis_config": f'bind 0.0.0.0\nprotected-mode yes\nrequirepass {redis_password}\nsave ""\nappendonly no\n',
    }
    for name, content in contents.items():
        fd, temporary = tempfile.mkstemp(prefix=".pending-", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            # Compose 文件秘密不支持重新映射 UID；目录 0700 阻止其他主机用户遍历。
            # 容器只获得显式授权的单文件挂载，文件 0444 允许非 root 进程读取。
            os.chmod(temporary, 0o444)
            os.link(temporary, directory / name, follow_symlinks=False)
        finally:
            os.unlink(temporary)


def main() -> None:
    os.umask(0o077)
    directory = Path(__file__).resolve().parent.parent / ".secrets"
    try:
        generate(directory)
    except FileExistsError:
        raise SystemExit("拒绝覆盖已有 .secrets 或符号链接；检查现有开发秘密与数据库卷后手工处理。")
    print("已生成本机开发秘密（目录 0700，授权挂载文件 0444）；未输出秘密。")


if __name__ == "__main__":
    main()
