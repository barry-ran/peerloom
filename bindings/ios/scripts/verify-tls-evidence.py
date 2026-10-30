#!/usr/bin/env python3
"""仅保存匿名 TLS 计数；失败也保留证据，不记录地址或异常正文。"""
import json
from pathlib import Path
import sys

COUNTERS = ('accepted_tcp', 'rejected_handshakes', 'accepted_handshakes',
            'handshake_timeout', 'other_io_error')


def verify(source, destination):
    state = json.loads(Path(source).read_text())
    if not isinstance(state, dict) or any(
        type(state.get(key)) is not int or state[key] < 0 for key in COUNTERS
    ):
        raise ValueError('TLS 匿名计数必须是非负整数')
    # 保留原成功字段，严格白名单；先写失败证据，再执行原有安全门禁。
    with Path(destination).open('x') as output:
        json.dump({key: state[key] for key in COUNTERS}, output)
        output.write('\n')
    assert state['rejected_handshakes'] >= 1 and state['accepted_handshakes'] == 0, '真实自签 TLS 拒绝证据不足'


if __name__ == '__main__':
    verify(sys.argv[1], sys.argv[2])
