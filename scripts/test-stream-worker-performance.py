#!/usr/bin/env python3
"""交错测量真实 SDK stream worker 满队列 CPU 与容量恢复时延；不降低授权复核频率。"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import time

TEST = 'sdk::channels::stream::tests::worker_performance::sdk_worker_backpressure_performance'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', action='append', required=True, help='标记=device-core测试程序')
    parser.add_argument('--output', required=True)
    parser.add_argument('--connections', default='1,32,100,300,500')
    parser.add_argument('--sizes', default='64,16384')
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--resume-rounds', type=int, default=200)
    parser.add_argument('--count-polls', action='store_true', help='仅独立profile，不能与正式CPU数据混用')
    args = parser.parse_args()
    variants = [(name, str(Path(path).resolve())) for name, path in
                (value.split('=', 1) for value in args.binary)]
    identities = {name: hashlib.sha256(Path(path).read_bytes()).hexdigest()
                  for name, path in variants}
    env = dict(os.environ, CLK_TCK=str(os.sysconf('SC_CLK_TCK')),
               PEERLOOM_PERF_RESUME_ROUNDS=str(args.resume_rounds))
    env.pop('LD_PRELOAD', None)
    env.pop('PEERLOOM_PERF_POLL_COUNTS', None)
    if args.count_polls:
        env['PEERLOOM_PERF_POLL_COUNTS'] = '1'
    with Path(args.output).open('x') as log:
        log.write(json.dumps({'kind': 'environment', 'platform': platform.platform(),
                              'clock_ticks': env['CLK_TCK'], 'threads': 4,
                              'binaries': identities, 'args': vars(args)}) + '\n')
        log.flush()
        for size in map(int, args.sizes.split(',')):
            for connections in map(int, args.connections.split(',')):
                env.update(PEERLOOM_PERF_BYTES=str(size), PEERLOOM_PERF_CONNECTIONS=str(connections))
                for repeat in range(args.repeats):
                    order = variants if repeat % 2 == 0 else list(reversed(variants))
                    for name, binary in order:
                        started = time.monotonic()
                        child = subprocess.run([binary, TEST, '--ignored', '--exact', '--nocapture',
                                                '--test-threads=1'], env=env, capture_output=True,
                                               text=True, timeout=650)
                        record = {'variant': name, 'repeat': repeat, 'connections': connections,
                                  'bytes': size, 'process_wall_s': time.monotonic() - started,
                                  'exit_code': child.returncode, 'stderr': child.stderr}
                        # libtest can print its test-name prefix on the same line.
                        # Require one complete JSON object and successful process,
                        # not a favourable substring or a partial test result.
                        marker = '{"kind":"sdk_worker_backpressure"'
                        records = [marker + line.partition(marker)[2]
                                   for line in child.stdout.splitlines() if marker in line]
                        record['valid'] = child.returncode == 0 and len(records) == 1
                        if record['valid']:
                            record.update(json.loads(records[0]))
                        else:
                            record['stdout'] = child.stdout
                        log.write(json.dumps(record) + '\n')
                        log.flush()
                        print(json.dumps(record), flush=True)
                        if not record['valid']:
                            raise SystemExit('失败记录已保留；不接纳部分输出或替换失败样本')


if __name__ == '__main__':
    main()
