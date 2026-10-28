#!/usr/bin/env python3
"""Keep crash categories/stack locations; never retain arbitrary device log messages."""
import re
import sys


def sanitize(line):
    if 'JNI DETECTED ERROR IN APPLICATION' in line:
        return 'CheckJNI detected an error'
    if re.search(r'Fatal signal \d+ \(', line):
        match = re.search(r'Fatal signal (\d+) \((SIG[A-Z0-9]+)\)', line)
        return f'native fatal signal={match[1]} category={match[2]}' if match else None
    frame = re.search(r'\bat ([A-Za-z0-9_.$]+)\(([A-Za-z0-9_.$]+\.(?:java|kt):\d+|Native Method|Unknown Source)\)', line)
    if frame:
        return f'at {frame[1]}({frame[2]})'
    error = re.search(r'\b((?:[a-zA-Z_][\w$]*\.)+[A-Za-z_$][\w$]*(?:Exception|Error))\b', line)
    if error:
        return f'exception_class={error[1]}'
    # Process names and PID only. Drop unstructured system-provided reasons.
    instrumentation = re.search(r'Crash of app (io\.peerloom\.sdk\.test(?::storeProbe)?) running instrumentation', line)
    if instrumentation:
        return f'instrumented_process_crashed name={instrumentation[1]}'
    process = re.search(r'\bProcess (io\.peerloom\.sdk\.test(?::storeProbe)?) \(pid (\d+)\) has died', line)
    if process:
        return f'process_died name={process[1]} pid={process[2]}'
    kill = re.search(r'\bKilling (\d+):io\.peerloom\.sdk\.test(?::storeProbe)?/', line)
    if kill:
        return f'process_killed pid={kill[1]} instrumentation_reason={"instrumentation" in line.lower()}'
    if 'Force stopping io.peerloom.sdk.test' in line:
        return f'package_force_stopped instrumentation_reason={"instrumentation" in line.lower()}'
    memory = re.search(r'\bstore-memory (phase=(?:before-bind|bound|probe-lock-held|caller-lock-held|after-kill-recovery|after-unbind) pid=\d+ pss_kib=\d+ importance=\d+ caller_count=\d+ probe_count=\d+|unavailable)(?=\s|$)', line)
    if memory:
        return f'store-memory {memory[1]}'
    alive = re.search(r'\bstore-alive phase=(before-contention|after-timeout) pid=(\d+)(?=\s|$)', line)
    if alive:
        return f'store-alive phase={alive[1]} pid={alive[2]}'
    probe = re.search(r'\bstore-probe-(bound pid=\d+|request kind=\d+ pid=\d+|cas-(?:start|success|conflict) pid=\d+|error category=[A-Za-z]+(?:Exception|Error) pid=\d+|exit pid=\d+ reason=\d+ status=\d+ importance=\d+)', line)
    if probe:
        return f'store-probe-{probe[1]}'
    stage = re.search(r'\bstore-process (bound caller_pid=\d+|CAS local=\d+ remote=\d+ remote_pid=\d+|remote-lock-held|local-lock-timeout-confirmed|remote-disconnected|instrumentation_targets=(?:<default>|\*|io\.peerloom\.sdk\.test(?::storeProbe)?))', line)
    if stage:
        return f'store-process {stage[1]}'
    trust = re.search(r'TLS fixture trust policy=(application-policy|android-ca-store) outcome=(trusted|[A-Za-z]+Exception)', line)
    if trust:
        return f'TLS fixture trust policy={trust[1]} outcome={trust[2]}'
    tls = re.search(r'TLS test server rejected: ([A-Za-z]+Exception); cause=(null|[A-Za-z]+Exception)', line)
    if tls:
        return f'TLS test server rejected: {tls[1]}; cause={tls[2]}'
    phase = re.search(r'\bstore-probe-kill pid=(\d+)\b', line)
    if phase:
        return f'store-probe-kill pid={phase[1]}'
    return None


if __name__ == '__main__':
    for index, line in enumerate(sys.stdin):
        if index >= 20000:
            print('diagnostic input bound reached')
            break
        result = sanitize(line)
        if result:
            print(result)
