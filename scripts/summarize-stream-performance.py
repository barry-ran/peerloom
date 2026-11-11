#!/usr/bin/env python3
"""按运行配对汇总性能数据；严格拒绝无效、重复或缺失配对，不筛选有利样本。"""
import argparse
import collections
import json
import math
from pathlib import Path
import random
import statistics


METRICS = {
    'stream': ['cpu_ns_per_byte', 'mib_per_s', 'rtt_p50_us', 'rtt_p95_us', 'rtt_p99_us'],
    'worker': ['idle_cpu_ns_per_worker_s', 'transfer_cpu_ns_per_byte',
               'paced_mib_per_s', 'resume_p50_us', 'resume_p95_us', 'resume_p99_us'],
}


def summarize(rows, baseline, candidate, pairs, mode):
    if baseline == candidate or pairs < 2:
        raise ValueError('需要两个不同版本和至少两对完整运行')
    groups = collections.defaultdict(dict)
    size_key = 'size' if mode == 'stream' else 'bytes'
    for row in rows:
        if row.get('kind') == 'environment':
            continue
        expected_kind = 'measurement' if mode == 'stream' else 'sdk_worker_backpressure'
        if row.get('kind') != expected_kind:
            raise ValueError('记录类型与测量模式不符')
        if mode == 'worker' and row.get('poll_counting') is not False:
            raise ValueError('正式 worker 汇总必须明确关闭 poll 插桩')
        if not row.get('valid') or row.get('exit_code') != 0:
            raise ValueError('含无效或失败运行；先调查，不能悄悄忽略')
        if row['variant'] not in (baseline, candidate):
            raise ValueError('出现未指定版本')
        case = (row['connections'], row[size_key])
        key = (row['repeat'], row['variant'])
        if key in groups[case]:
            raise ValueError(f'重复配对槽位：{case}, {key}')
        groups[case][key] = row
    if not groups:
        raise ValueError('没有测量数据')
    output = []
    expected = {(repeat, variant) for repeat in range(pairs)
                for variant in (baseline, candidate)}
    for (connections, size), samples in sorted(groups.items()):
        if set(samples) != expected:
            raise ValueError(f'配对不完整或轮次不符：{connections}, {size}')
        result = {'connections': connections, 'size': size, 'pairs': pairs,
                  'baseline': baseline, 'candidate': candidate, 'metrics': {}}
        for metric in METRICS[mode]:
            before = [samples[i, baseline][metric] for i in range(pairs)]
            after = [samples[i, candidate][metric] for i in range(pairs)]
            if any(not math.isfinite(v) or v <= 0 for v in before + after):
                raise ValueError(f'非正或非有限指标：{metric}')
            logs = [math.log(b / a) for a, b in zip(before, after)]
            rng = random.Random(0)
            boot = sorted(statistics.mean(rng.choices(logs, k=pairs))
                          for _ in range(10000))
            percent = lambda value: 100 * math.expm1(value)
            result['metrics'][metric] = {
                'paired_percent_change': percent(statistics.mean(logs)),
                'bootstrap95': [percent(boot[249]), percent(boot[9749])],
                'pair_percent_changes': [percent(value) for value in logs],
                'baseline_median': statistics.median(before),
                'candidate_median': statistics.median(after),
                'baseline_range': [min(before), max(before)],
                'candidate_range': [min(after), max(after)],
            }
        output.append(result)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('--baseline', default='baseline')
    parser.add_argument('--candidate', required=True)
    parser.add_argument('--pairs', type=int, default=5)
    parser.add_argument('--mode', choices=METRICS, default='stream')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.input.read_text().splitlines()]
    results = summarize(rows, args.baseline, args.candidate, args.pairs, args.mode)
    with args.output.open('x') as output:
        json.dump(results, output, indent=2, ensure_ascii=False)
        output.write('\n')
    for case in results:
        print(f"{case['connections']}连接 × {case['size']}B，{case['pairs']}对")
        for name, metric in case['metrics'].items():
            low, high = metric['bootstrap95']
            print(f"  {name}: {metric['paired_percent_change']:+.2f}% "
                  f"[{low:+.2f}, {high:+.2f}]")


if __name__ == '__main__':
    main()
