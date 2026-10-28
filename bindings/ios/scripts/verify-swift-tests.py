#!/usr/bin/env python3
# MIT — Copyright (c) 2026 Peerloom contributors.
"""严格核对 macOS XCTest discovery 与两个 suite 的实际完成，不接受零测试成功。"""
import json
from pathlib import Path
import re
import sys

EXPECTED = {
    "NativeCoreTests": {
        "testRetainedEventRechecksAtSynchronousConsumption",
        "testRetainedEventsKeepBoundedCreditsUntilConsumption",
        "testReadRechecksAfterCallerActorResumes",
        "testTypedChildMetadataAndPartialWriteResult",
        "testEarlyCompletionsAndQuiescentRelease",
        "testExpiredBufferedReadyAndMessageAreNotDelivered",
        "testHostEventOverflowStopsInsteadOfDroppingAndContinuing",
        "testRealNativeCreateLoadAndShutdown",
        "testRealNativeRejectsUntrustedTLS",
    },
    "KeychainTests": {
        "testSaveLoadCASAndPersistentDeleteTombstone",
        "testConcurrentCASHasExactlyOneWinner",
        "testMainThreadAndOverflowFailClosed",
        "testLockedKeychainDoesNotBecomeEmptyOrPrompt",
        "testCrossProcessCASUsingIsolatedKeychain",
    },
}


def discovery(path):
    names = [line.strip() for line in path.read_text().splitlines() if line.strip()]
    expected = {"PeerloomSwiftTests." + suite + "/" + method
                for suite, methods in EXPECTED.items() for method in methods}
    if len(names) != 14 or set(names) != expected:
        raise ValueError("XCTest discovery 必须精确覆盖当前两个 suite 的全部 14 项")


def suite_completed(suite, path):
    content = path.read_text()
    for method in EXPECTED[suite]:
        # Actual XCTest pass lines; declaration/discovery/started alone are not evidence.
        pattern = r"(?m)^Test Case [^\n]*\b" + re.escape(method) + r"\b[^\n]*\bpassed\b"
        if not re.search(pattern, content):
            raise ValueError(suite + "/" + method + " 缺少实际 passed 记录")


def aggregate(out):
    discovery(out / "phase-macos-discovery.stdout")
    statuses = []
    for suite in EXPECTED:
        name = "macos-" + suite
        status = json.loads((out / ("phase-" + name + ".json")).read_text())
        if status["classification"] != "passed" or status["exit_code"] != 0:
            raise ValueError(suite + " 未通过，其他 suite 仅用于诊断")
        suite_completed(suite, out / ("phase-" + name + ".log"))
        statuses.append(status)
    result = {"classification": "passed", "exit_code": 0, "test_count": 14,
              "started_at": min(s["started_at"] for s in statuses),
              "finished_at": max(s["finished_at"] for s in statuses),
              "elapsed_seconds": sum(s["elapsed_seconds"] for s in statuses)}
    with (out / "phase-macos-swift.json").open("x") as stream:
        json.dump(result, stream, sort_keys=True, indent=2)


if __name__ == "__main__":
    try:
        if len(sys.argv) == 3 and sys.argv[1] == "discovery":
            discovery(Path(sys.argv[2]))
        elif len(sys.argv) == 3 and sys.argv[1] == "aggregate":
            aggregate(Path(sys.argv[2]))
        else:
            raise ValueError("需要 discovery <stdout> 或 aggregate <输出目录>")
    except (ValueError, OSError, KeyError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
