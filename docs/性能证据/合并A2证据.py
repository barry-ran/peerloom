#!/usr/bin/env python3
"""重现会话中断后的固定槽位合并；不依据性能值取舍任何样本。"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ORIGINAL = ROOT / 'A2中断原始.jsonl'
RESUMED = ROOT / 'A2补测原始.jsonl'
assert hashlib.sha256(ORIGINAL.read_bytes()).hexdigest() == (
    '0182dfd37a21fdf29785d92571acdd51c93f90cd12b6a1b3919c17c5cf25bf02')
original = [json.loads(line) for line in ORIGINAL.read_text().splitlines()]
resumed = [json.loads(line) for line in RESUMED.read_text().splitlines()]
assert len(original) == 94 and len(resumed) == 9
assert original[0]['binaries'] == resumed[0]['binaries']
for key in ['platform', 'cpu_count', 'clock_ticks', 'threads']:
    assert original[0][key] == resumed[0][key]


def slot(row):
    return row['connections'], row['size'], row['repeat'], row['variant']


assert slot(original[-1]) == (500, 16384, 1, 'full-frame-owned')
assert {slot(row) for row in resumed[1:]} == {
    (500, 16384, repeat, variant) for repeat in range(1, 5)
    for variant in ['baseline', 'full-frame-owned']}
measurements = original[1:-1] + resumed[1:]
assert len(measurements) == len({slot(row) for row in measurements}) == 100
assert {slot(row) for row in measurements} == {
    (connections, size, repeat, variant)
    for connections in [1, 32, 100, 300, 500] for size in [64, 16384]
    for repeat in range(5) for variant in ['baseline', 'full-frame-owned']}
assert all(row['valid'] and row['exit_code'] == 0
           and 'PERF_MEASURE_END retries=0' in row['stderr']
           for row in measurements)
header = dict(original[0], sources=[ORIGINAL.name, RESUMED.name],
              excluded_unpaired_slot=list(slot(original[-1])),
              exclusion_reason='中断留下单边样本；补测整个配对，不按指标筛选')
with (ROOT / 'A2完整矩阵.jsonl').open('x') as output:
    for row in [header] + measurements:
        output.write(json.dumps(row, ensure_ascii=False) + '\n')
print('完整性校验通过：10 条件 × 5 对 × 2 版本 = 100 条有效测量')
