#!/usr/bin/env python3
# MIT — Copyright (c) 2026 Peerloom contributors.
"""原生测试进程组 watchdog；只终止自己创建的测试组，不操作 SDK 对象。"""
import argparse
import datetime
from contextlib import ExitStack
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time


def run(command, timeout, grace, log_path, status_path, stdout_path=None):
    started = time.monotonic()
    status = {"started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "timeout_seconds": timeout, "classification": "starting"}
    interrupted = []
    previous = {}
    process = None
    selector = selectors.DefaultSelector()
    # Existing evidence must not be overwritten by a repeated phase.
    with ExitStack() as files:
        evidence = files.enter_context(open(status_path, "x", encoding="utf-8"))
        log = files.enter_context(open(log_path, "xb"))
        stdout_file = files.enter_context(open(stdout_path, "xb")) if stdout_path else None
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, lambda number, _: interrupted.append(number))
        result = 127
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       stdin=subprocess.DEVNULL, start_new_session=True)
            os.set_blocking(process.stdout.fileno(), False)
            os.set_blocking(process.stderr.fileno(), False)
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            deadline = started + timeout
            terminate_at = None
            killed_at = None
            streams_open = 2
            reason = None
            while True:
                now = time.monotonic()
                if reason is None and (interrupted or now >= deadline):
                    reason = "interrupted" if interrupted else "timeout"
                    terminate_at = now
                    signal_group(process.pid, signal.SIGTERM)
                if terminate_at is not None and killed_at is None and now >= terminate_at + grace:
                    # The leader may already have exited; descendants still belong to our group.
                    signal_group(process.pid, signal.SIGKILL)
                    killed_at = now
                for key, _ in selector.select(0.05):
                    chunk = os.read(key.fd, 65536)
                    if chunk:
                        if stdout_file is not None and key.data == "stdout":
                            stdout_file.write(chunk)
                            stdout_file.flush()
                        log.write(chunk)
                        log.flush()
                        sys.stdout.buffer.write(chunk)
                        sys.stdout.buffer.flush()
                    else:
                        selector.unregister(key.fileobj)
                        streams_open -= 1
                code = process.poll()
                if reason is None and code is not None and not streams_open:
                    result = code if code >= 0 else 128 - code
                    status["classification"] = "passed" if code == 0 else "failed"
                    break
                if reason is not None and killed_at is not None:
                    # Drain output, but do not wait indefinitely on inherited pipes or a
                    # kernel-stuck child. A failed reap remains visible in the evidence.
                    if (code is not None and not streams_open) or now >= killed_at + 1:
                        result = 124 if reason == "timeout" else 128 + interrupted[0]
                        status["classification"] = reason
                        break
            try:
                status["child_returncode"] = process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                status["child_returncode"] = None
                status["reap_failed"] = True
        except OSError:
            status["classification"] = "launch-or-io-error"
        finally:
            if process is not None:
                # Also reap ordinary children after failure. Never target an unrelated process.
                signal_group(process.pid, signal.SIGTERM)
                if process.poll() is None:
                    try:
                        process.wait(timeout=grace)
                    except subprocess.TimeoutExpired:
                        signal_group(process.pid, signal.SIGKILL)
                        try:
                            process.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            status["reap_failed"] = True
                signal_group(process.pid, signal.SIGKILL)
                process.stdout.close()
                process.stderr.close()
            selector.close()
            for signum, handler in previous.items():
                signal.signal(signum, handler)
            status["elapsed_seconds"] = round(time.monotonic() - started, 3)
            status["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            status["exit_code"] = result
            # Deliberately omit argv/environment: they could contain credentials.
            json.dump(status, evidence, ensure_ascii=False, sort_keys=True, indent=2)
            evidence.write("\n")
            print("\nwatchdog: " + status["classification"] + " exit=" + str(result), flush=True)
    return result


def signal_group(pid, signum):
    try:
        os.killpg(pid, signum)
    except ProcessLookupError:
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, required=True)
    parser.add_argument("--grace", type=float, default=2)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--status", type=Path, required=True)
    parser.add_argument("--stdout", type=Path, help="可选：只保存 stdout，便于严格解析 JSON/UUID")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command or not 0 < args.timeout <= 3600 or not 0 < args.grace <= 10:
        parser.error("需要命令、0–3600 秒期限和 0–10 秒终止宽限")
    os.umask(0o077)
    try:
        return run(command, args.timeout, args.grace, args.log, args.status, args.stdout)
    except FileExistsError:
        print("拒绝覆盖已有测试证据", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
