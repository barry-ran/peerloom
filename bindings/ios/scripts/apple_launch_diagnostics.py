# MIT — Copyright (c) 2026 Peerloom contributors.
"""XCTest 启动停滞的只读旁路取证；不改变测试命令、deadline 或结果。"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys


AFTER_SECONDS = 60
COMMAND_TIMEOUT = 10
MAX_BYTES = 1024 * 1024
HOST_PROCESSES = ("CoreSimulatorService", "com.apple.CoreSimulator.CoreSimulatorService", "debugserver")
SENSITIVE = re.compile(r"environment|arguments|argv|command.line|password|passwd|secret|token|credential|authorization|bearer|cookie|DYLD_|TLS_ORIGIN", re.I)


def host_predicate(pid, command):
    # 只读日志曾被启动前的全局 debug 噪声撑满；在源头收窄，而非放大证据上限。
    related = ['eventMessage CONTAINS[c] "io.peerloom.validation.simulatorhost"']
    for option, value in zip(command, command[1:]):
        if option == "-destination":
            match = re.search(r"(?:^|,)id=([0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12})(?:,|$)", value)
            if match:
                related.append(f'eventMessage CONTAINS[c] "{match.group(1)}"')
    # 保留不带设备 ID 的启动服务错误；绝不拼接原始 destination/命令参数。
    related.extend(f'eventMessage CONTAINS[c] "{word}"' for word in ("error", "fail", "denied", "timeout", "timed out"))
    services = " OR ".join(f'process == "{name}"' for name in HOST_PROCESSES)
    return f'processID == {pid} OR (({services}) AND ({" OR ".join(related)}))'


def safe_text(value):
    value = re.sub(r"https?://[^\s\"<>]+", "<url>", value)
    return re.sub(r"/Users/[^/\s]+", "<home>", value)


def sample_evidence(raw):
    # sample 的头部可能包含路径/调用信息，只保留符号化调用栈，不保存 argv 或环境。
    text = raw.decode("utf-8", errors="replace")
    if "Call graph:" not in text:
        raise ValueError("missing call graph")
    stack = text.split("Call graph:", 1)[1]
    stack = re.split(r"\n(?:Total number in stack|Sort by top of stack|Binary Images:)", stack, maxsplit=1)[0]
    return "Call graph:\n" + "\n".join(safe_text(line) for line in stack.splitlines()
                                        if not SENSITIVE.search(line))


def log_evidence(raw, pid):
    entries = json.loads(raw)
    if not isinstance(entries, list) or len(entries) > 10000:
        raise ValueError("invalid log records")
    selected = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("invalid log record")
        process = Path(str(entry.get("processImagePath", ""))).name
        own = entry.get("processID") == pid
        if not own and process not in HOST_PROCESSES:
            continue
        message = entry.get("eventMessage")
        if not isinstance(message, str) or SENSITIVE.search(message):
            continue
        # 不转存整个系统日志对象：只保留定位启动问题需要的字段。
        selected.append({"timestamp": entry.get("timestamp"), "process": process,
                         "process_id": entry.get("processID"), "message": safe_text(message)})
    return selected


class LaunchDiagnostics:
    def __init__(self, target, command, log_path, started):
        self.target = target
        self.log_path = Path(log_path)
        self.started = started
        self.predicate = host_predicate(target.pid, command)
        self.attempted = False
        self.collectors = []
        self.unreaped = []
        self.errors = []
        self.enabled = (sys.platform == "darwin" and Path(command[0]).name == "xcodebuild"
                        and "test-without-building" in command)

    @property
    def holds_target_pid(self):
        # sample 退出或已成功收到 SIGKILL 前不 reap 测试进程，避免 PID 复用。
        return any(item["name"] == "sample" for item in self.collectors)

    def tick(self, now):
        self._reap_pending()
        if not self.enabled:
            return
        if not self.attempted and now >= self.started + AFTER_SECONDS:
            self.attempted = True
            if self.target.poll() is not None:
                return
            pid = self.target.pid
            commands = (
                ("sample", ["/usr/bin/sample", str(pid), "5", "10", "-file", "/dev/stdout"]),
                ("host-log", ["/usr/bin/log", "show", "--last", "1m", "--style", "json",
                              "--info", "--predicate", self.predicate]),
            )
            for name, command in commands:
                item = None
                try:
                    child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                             stderr=subprocess.DEVNULL, start_new_session=True)
                    item = {"name": name, "child": child, "deadline": now + COMMAND_TIMEOUT,
                            "data": bytearray(), "eof": False}
                    self.collectors.append(item)
                    os.set_blocking(child.stdout.fileno(), False)
                except OSError:
                    self.errors.append(name + ":launch-error")
                    if item is not None:
                        self._finish(item, "configure-error")
        for item in self.collectors[:]:
            if item.get("stop_failed"):
                if item["child"].poll() is not None:
                    self._finish(item, "stop-failed-exited")
                continue
            try:
                # 每轮固定最多读取 64 KiB，诊断输出不能饿死测试 watchdog。
                chunk = os.read(item["child"].stdout.fileno(), 65536)
                if not chunk:
                    item["eof"] = True
                item["data"].extend(chunk)
            except BlockingIOError:
                pass
            except OSError:
                self._finish(item, "read-error")
                continue
            if len(item["data"]) > MAX_BYTES:
                self._finish(item, "output-limit")
            elif now >= item["deadline"]:
                self._finish(item, "timeout")
            elif item["child"].poll() is not None and item["eof"]:
                self._finish(item, "completed")

    def _finish(self, item, classification):
        child = item["child"]
        # 终止失败不丢弃所有权或释放采样对象的 PID；后续只非阻塞观察。
        if child.poll() is None:
            try:
                child.kill()
            except OSError:
                if not item.get("stop_failed"):
                    self.errors.append(item["name"] + ":stop-failed")
                item["stop_failed"] = True
                return
        try:
            # 仅终止本次创建的两个诊断工具；绝不向采样对象或系统服务发信号。
            try:
                child.wait(timeout=0.2)
            except subprocess.TimeoutExpired:
                classification = "reap-timeout"
                self.unreaped.append(child)
            evidence = {"classification": classification, "target_pid": self.target.pid,
                        "exit_code": child.returncode, "timeout_seconds": COMMAND_TIMEOUT,
                        "max_bytes": MAX_BYTES, "observational_only": True}
            if classification == "completed" and child.returncode == 0:
                try:
                    evidence["evidence"] = (sample_evidence(item["data"]) if item["name"] == "sample"
                                            else log_evidence(item["data"], self.target.pid))
                except (ValueError, TypeError, RecursionError):
                    evidence["classification"] = "invalid-output"
            path = self.log_path.with_name(self.log_path.stem + "-" + item["name"] + ".log")
            # 永不覆盖前次证据；不把未经筛选的工具输出写到任何持久文件或 stdout。
            encoded = (json.dumps(evidence, ensure_ascii=True, indent=2) + "\n").encode("utf-8")
            if len(encoded) > MAX_BYTES:
                evidence.pop("evidence", None)
                evidence["classification"] = "output-limit"
                encoded = (json.dumps(evidence) + "\n").encode("utf-8")
            with path.open("xb") as output:
                output.write(encoded)
        except (OSError, ValueError, UnicodeError, RecursionError, TypeError):
            self.errors.append(item["name"] + ":cleanup-or-evidence-error")
        finally:
            try:
                child.stdout.close()
            except OSError:
                self.errors.append(item["name"] + ":pipe-close-error")
            self.collectors.remove(item)

    def _reap_pending(self):
        # SIGKILL 后内核尚未完成退出时仍保留回收句柄，但不无限等待或重复发信号。
        self.unreaped[:] = [child for child in self.unreaped if child.poll() is None]

    def close(self):
        for item in self.collectors[:]:
            self._finish(item, "cancelled")
        self._reap_pending()

    def summary(self):
        return {"enabled": self.enabled, "attempted": self.attempted, "errors": self.errors,
                "unreaped_pids": [child.pid for child in self.unreaped],
                "unstopped_pids": [item["child"].pid for item in self.collectors],
                "after_seconds": AFTER_SECONDS, "observational_only": True}
