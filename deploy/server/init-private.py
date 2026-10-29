#!/usr/bin/env python3
# MIT — Copyright (c) 2026 Peerloom contributors.
"""为新解压的服务器包生成私有本机秘密；不覆盖、不创建账户、不启动服务。"""
import argparse
import base64
import os
from pathlib import Path
import secrets
import stat


def open_directory(path):
    absolute = Path(os.path.abspath(path))
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in absolute.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            trusted = info.st_uid in (0, os.geteuid())
            writable = info.st_mode & 0o022
            sticky = info.st_mode & stat.S_ISVTX
            if not trusted or (writable and not sticky):
                raise ValueError('untrusted directory ancestor')
        return fd
    except BaseException:
        os.close(fd)
        raise


def generate(package):
    parent = open_directory(package)
    directory = None
    try:
        # Exclusive mkdir rejects ALL existing entries, including symlinks.
        os.mkdir('.secrets', mode=0o700, dir_fd=parent)
        directory = os.open('.secrets', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        info = os.fstat(directory)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('private directory permissions rejected')
        postgres = secrets.token_hex(32)
        redis = secrets.token_hex(32)
        contents = {
            'postgres_password': postgres + '\n',
            'database_url': f'postgres://peerloom:{postgres}@postgres:5432/peerloom?sslmode=disable\n',
            'redis_password': redis + '\n',
            'redis_config': f'bind 0.0.0.0\nprotected-mode yes\nrequirepass {redis}\nsave ""\nappendonly no\n',
            'replay_key': base64.b64encode(secrets.token_bytes(32)).decode('ascii') + '\n',
        }
        for name, value in contents.items():
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(value.encode('ascii'))
                stream.flush()
                os.fsync(stream.fileno())
                # Only this newly-created file. Parent stays 0700: no host traversal.
                # Compose bind-secrets do not translate owner IDs for non-root readers.
                os.fchmod(stream.fileno(), 0o444)
        os.fsync(directory)
        os.fsync(parent)
    finally:
        if directory is not None:
            os.close(directory)
        os.close(parent)
    # On partial failure retain the owned directory, fail closed on every rerun.


def read_tls_source(path, private=False):
    absolute = Path(os.path.abspath(path))
    parent = open_directory(absolute.parent)
    try:
        fd = os.open(absolute.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
                or info.st_mode & 0o022 or (private and info.st_mode & 0o077)
                or info.st_size < 1 or info.st_size > 1024 * 1024):
            raise ValueError('unsafe TLS input')
        data = stream.read(1024 * 1024 + 1)
        after = os.fstat(stream.fileno())
        if (len(data) != info.st_size or after.st_size != info.st_size
                or after.st_mtime_ns != info.st_mtime_ns or after.st_ctime_ns != info.st_ctime_ns):
            raise ValueError('TLS input changed')
        return data


def stage_tls(package, certificate, private_key):
    # All source reads/validation finish before creating any destination. Original files are never chmodded.
    contents = {'certificate.pem': read_tls_source(certificate),
                'private-key.pem': read_tls_source(private_key, private=True)}
    parent = open_directory(package)
    directory = None
    try:
        os.mkdir('.tls', mode=0o700, dir_fd=parent)
        directory = os.open('.tls', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        info = os.fstat(directory)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('unsafe TLS destination')
        for name, data in contents.items():
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
                os.fchmod(stream.fileno(), 0o444)
        os.fsync(directory)
        os.fsync(parent)
    finally:
        if directory is not None:
            os.close(directory)
        os.close(parent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage-tls', action='store_true')
    parser.add_argument('--certificate', type=Path)
    parser.add_argument('--private-key', type=Path)
    args = parser.parse_args()
    if args.stage_tls != bool(args.certificate and args.private_key) or (not args.stage_tls and (args.certificate or args.private_key)):
        parser.error('--stage-tls requires both --certificate and --private-key')
    os.umask(0o077)
    try:
        package = Path(os.path.abspath(__file__)).parent.parent
        if args.stage_tls:
            stage_tls(package, args.certificate, args.private_key)
        else:
            generate(package)
    except (OSError, ValueError):
        raise SystemExit('拒绝初始化：目标已存在、路径或权限不安全；未输出秘密，未修改已有文件。') from None
    print('新私有副本已生成：父目录0700、授权单文件只读0444；未创建账号或启动服务。信任本机Docker守护进程。')


if __name__ == '__main__':
    main()
