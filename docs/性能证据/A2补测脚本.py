#!/usr/bin/env python3
"""同机交错运行真实加密环回字节流基准；只接纳完成字节及 FIN 校验的退出码 0。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import time
from datetime import datetime, timezone


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', action='append', required=True, help='标记=可执行文件')
    parser.add_argument('--output', required=True)
    parser.add_argument('--connections', default='500')
    parser.add_argument('--sizes', default='16384')
    parser.add_argument('--repeats', type=int, default=5)
    parser.add_argument('--small-roundtrips', type=int, default=100000)
    parser.add_argument('--large-roundtrips', type=int, default=32000)
    args = parser.parse_args()
    variants = [(name, str(Path(path).resolve())) for name, path in
                (value.split('=', 1) for value in args.binary)]
    identities = {name: hashlib.sha256(Path(path).read_bytes()).hexdigest()
                  for name, path in variants}
    output = Path(args.output)
    if output.exists():
        raise SystemExit('拒绝覆盖已有测量文件')
    environment = dict(os.environ, CLK_TCK=str(os.sysconf('SC_CLK_TCK')),
                       PEERLOOM_PERF_THREADS='4')
    environment.pop('LD_PRELOAD', None)
    with output.open('x') as log:
        log.write(json.dumps({'kind': 'environment', 'utc': datetime.now(timezone.utc).isoformat(), 'resume_reason': '原会话中断；保留已完成46对，旧500x16384 repeat1孤立候选仅归档，新跑repeat1至4完整配对', 'platform': platform.platform(),
                              'cpu_count': os.cpu_count(), 'clock_ticks': environment['CLK_TCK'],
                              'threads': 4, 'binaries': identities, 'args': vars(args)}) + '\n')
        log.flush()
        for size in map(int, args.sizes.split(',')):
            total = args.small_roundtrips if size < 1024 else args.large_roundtrips
            for connections in map(int, args.connections.split(',')):
                rounds = max(1, (total + connections - 1) // connections)
                for repeat in range(1, args.repeats):
                    # AB/BA 对称交错，避免先跑完一版再跑另一版的时间偏差。
                    order = variants if repeat % 2 == 0 else list(reversed(variants))
                    for name, binary in order:
                        before = time.monotonic()
                        result = subprocess.run([binary, str(connections), str(size),
                                                 str(rounds), '20'], env=environment,
                                                capture_output=True, text=True, timeout=190)
                        record = {'kind': 'measurement', 'variant': name, 'repeat': repeat,
                                  'connections': connections, 'size': size,
                                  'utc': datetime.now(timezone.utc).isoformat(), 'process_wall_s': time.monotonic() - before,
                                  'exit_code': result.returncode, 'stderr': result.stderr}
                        if result.returncode == 0:
                            record.update(json.loads(result.stdout))
                            record['valid'] = record['wall_s'] >= 1.0
                        else:
                            record.update(valid=False, stdout=result.stdout)
                        log.write(json.dumps(record) + '\n')
                        log.flush()
                        print(json.dumps(record), flush=True)
                        if result.returncode:
                            raise SystemExit('基准失败；保留失败证据，不将部分输出算作收益')


if __name__ == '__main__':
    main()
