#!/usr/bin/env bash
# MIT — Copyright (c) 2026 Peerloom contributors.
set -euo pipefail
[[ $(uname -s) == Darwin ]] || { echo '需要真实 Apple runner' >&2; exit 2; }
: "${PEERLOOM_REPO_ROOT:?设置仓库根目录}"
: "${PEERLOOM_APPLE_OUTPUT:?设置 build-xcframework.sh 输出目录}"
export DEVELOPER_DIR=${DEVELOPER_DIR:-/Applications/Xcode_16.4.app/Contents/Developer}
[[ $(xcodebuild -version) == $'Xcode 16.4\nBuild version 16F6' ]] || exit 2
ROOT=$(cd "$PEERLOOM_REPO_ROOT" && pwd)
OUT=$(cd "$PEERLOOM_APPLE_OUTPUT" && pwd)
HERE=$(cd "$(dirname "$0")/.." && pwd)
TLS_DIR=$(mktemp -d "$OUT/tls-fixture.XXXXXX")
chmod 700 "$TLS_DIR"
DEVICE=''
TLS_PID=''
cleanup() {
  if [[ -n "$DEVICE" ]]; then xcrun simctl shutdown "$DEVICE" >/dev/null 2>&1 || true; xcrun simctl delete "$DEVICE" >/dev/null 2>&1 || true; fi
  if [[ -n "$TLS_PID" ]]; then kill "$TLS_PID" >/dev/null 2>&1 || true; wait "$TLS_PID" || true; fi
  rm -rf "$TLS_DIR" # Only the newly created private fixture; never an operator-supplied existing path.
}
trap cleanup EXIT
python3 "$HERE/scripts/tls-fixture.py" "$TLS_DIR" &
TLS_PID=$!
for _ in $(seq 1 100); do [[ -f "$TLS_DIR/state.json" ]] && break; kill -0 "$TLS_PID"; sleep 0.1; done
export PEERLOOM_TLS_ORIGIN
PEERLOOM_TLS_ORIGIN=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["origin"])' "$TLS_DIR/state.json")
export TEST_RUNNER_PEERLOOM_TLS_ORIGIN="$PEERLOOM_TLS_ORIGIN"
cd "$OUT/SwiftPackage"
swift build --product PeerloomStoreProbe
export PEERLOOM_STORE_PROBE_BIN
PEERLOOM_STORE_PROBE_BIN="$(swift build --show-bin-path)/PeerloomStoreProbe"
swift test --parallel
# Actual macOS system-trust negative tests; no certificate verification bypass.
(cd "$ROOT/src/device-sdk" && cargo test --locked -p device-core --test tls)
RUNTIME=com.apple.CoreSimulator.SimRuntime.iOS-18-5
TYPE=com.apple.CoreSimulator.SimDeviceType.iPhone-16
xcrun simctl list runtimes -j | python3 -c 'import json,sys; r=sys.argv[1]; assert any(v["identifier"]==r and v.get("isAvailable") for v in json.load(sys.stdin)["runtimes"]), "固定 iOS 18.5 runtime 不可用"' "$RUNTIME"
DEVICE=$(xcrun simctl create "PeerloomValidation-$$" "$TYPE" "$RUNTIME")
xcrun simctl boot "$DEVICE"
xcrun simctl bootstatus "$DEVICE" -b
# Xcode's Swift-package scheme builds an XCTest runner on the actual simulator.
xcodebuild -scheme PeerloomSwift -destination "platform=iOS Simulator,id=$DEVICE" \
  -derivedDataPath "$OUT/DerivedData-simulator" -resultBundlePath "$OUT/iOS模拟器测试.xcresult" \
  CODE_SIGNING_ALLOWED=NO test
xcrun xcresulttool get test-results summary --path "$OUT/iOS模拟器测试.xcresult" > "$OUT/iOS测试摘要.json"
python3 - "$OUT/iOS测试摘要.json" "$TLS_DIR/state.json" <<'PY'
import json,sys
summary=json.load(open(sys.argv[1]))
assert summary['totalTestCount'] >= 8 and summary['failedTests'] == 0, 'iOS XCTest 未实际执行足够用例或存在失败'
tls=json.load(open(sys.argv[2]))
assert tls['rejected_handshakes'] >= 2 and tls['accepted_handshakes'] == 0, 'macOS+iOS 真实自签TLS拒绝证据不足'
PY
# Build ONLY: no signing identity, provisioning profile, deployment or physical-device claim.
xcodebuild -scheme PeerloomSwift -destination 'generic/platform=iOS' \
  -derivedDataPath "$OUT/DerivedData-device" CODE_SIGNING_ALLOWED=NO \
  BUILD_LIBRARY_FOR_DISTRIBUTION=YES build
printf '%s\n' 'macOS XCTest/隔离临时 Keychain/跨进程 CAS、macOS/iOS自签TLS负向、iOS模拟器 XCTest 与 unsigned device build 已由本次脚本通过。' \
  '设备构建不等于真机验证；未进行生产签名、部署或法律清关。' > "$OUT/原生测试状态.txt"
# Only this successful path advances build evidence; earlier failures retain built-not-native-tested.
python3 - "$OUT" <<'PYMETA'
import json,sys
from pathlib import Path
out=Path(sys.argv[1])
p=out/'构建证据.json'
meta=json.loads(p.read_text())
meta['status']='native-tests-passed'
meta['native_validation']={
    'macos_swift_tests': True,
    'macos_isolated_keychain_and_process_cas': True,
    'macos_rust_system_trust_tests': True,
    'ios_simulator_xctest': True,
    'macos_ios_untrusted_tls_rejected': True,
    'ios_unsigned_device_build': True,
    'physical_device_test': False,
    'production_signing_or_deployment': False,
}
p.write_text(json.dumps(meta,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
(out/'发布审查状态.txt').write_text(
    '本次原生脚本已通过 macOS 与 iOS 模拟器测试；设备构建不等于真机验收。\n'
    '未进行生产签名或部署。MIT 仅覆盖本项目原代码；第三方仍遵守各自许可，notice/SBOM 不代表法律清关。\n')
PYMETA
