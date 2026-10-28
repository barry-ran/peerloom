#!/usr/bin/env bash
# MIT — Copyright (c) 2026 Peerloom contributors.
set -euo pipefail
[[ $(uname -s) == Darwin ]] || { echo '需要真实 Apple runner' >&2; exit 2; }
: "${PEERLOOM_REPO_ROOT:?设置仓库根目录}"
: "${PEERLOOM_APPLE_OUTPUT:?设置 build-xcframework.sh 输出目录}"
export DEVELOPER_DIR=${DEVELOPER_DIR:-/Applications/Xcode_16.4.app/Contents/Developer}
ROOT=$(cd "$PEERLOOM_REPO_ROOT" && pwd)
OUT=$(cd "$PEERLOOM_APPLE_OUTPUT" && pwd)
HERE=$(cd "$(dirname "$0")/.." && pwd)
PHASE=${2:-all}
[[ $# == 0 || ( $# == 2 && $1 == --stage ) ]] || exit 2
case "$PHASE" in all|macos-swift|macos-rust-tls|ios-simulator|ios-device|finalize|cleanup) ;; *) exit 2 ;; esac
if [[ "$PHASE" != cleanup ]]; then
  [[ $(xcodebuild -version) == $'Xcode 16.4\nBuild version 16F6' ]] || exit 2
fi
TLS_DIR=''
TLS_PID=''
DEVICE=''
run() {
  local name=$1 seconds=$2
  shift 2
  printf '\n[Apple phase start] %s\n' "$name"
  python3 "$HERE/scripts/watchdog.py" --timeout "$seconds" \
    --log "$OUT/phase-$name.log" --status "$OUT/phase-$name.json" -- "$@"
  printf '[Apple phase passed] %s\n' "$name"
}
run_capture() {
  local name=$1 seconds=$2
  shift 2
  printf '\n[Apple phase start] %s\n' "$name"
  python3 "$HERE/scripts/watchdog.py" --timeout "$seconds" \
    --log "$OUT/phase-$name.log" --status "$OUT/phase-$name.json" \
    --stdout "$OUT/phase-$name.stdout" -- "$@"
  printf '[Apple phase passed] %s\n' "$name"
}
cleanup() {
  if [[ -n "$DEVICE" ]]; then
    run "$PHASE-cleanup-shutdown" 30 xcrun simctl shutdown "$DEVICE" || true
    run "$PHASE-cleanup-delete" 30 xcrun simctl delete "$DEVICE" || true
  fi
  if [[ -n "$TLS_PID" ]]; then
    kill "$TLS_PID" >/dev/null 2>&1 || true
    # Only our fixture PID; bounded cleanup if its TLS syscall is still returning.
    for _ in $(seq 1 60); do kill -0 "$TLS_PID" >/dev/null 2>&1 || break; sleep 0.1; done
    kill -KILL "$TLS_PID" >/dev/null 2>&1 || true
    wait "$TLS_PID" 2>/dev/null || true
  fi
  if [[ -n "$TLS_DIR" ]]; then rm -rf "$TLS_DIR"; fi
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
start_tls() {
  TLS_DIR=$(mktemp -d "$OUT/tls-fixture.XXXXXX")
  chmod 700 "$TLS_DIR"
  python3 "$HERE/scripts/watchdog.py" --timeout 1200 --log "$OUT/phase-$PHASE-tls-server.log" \
    --status "$OUT/phase-$PHASE-tls-server.json" -- python3 "$HERE/scripts/tls-fixture.py" "$TLS_DIR" &
  TLS_PID=$!
  for _ in $(seq 1 100); do [[ -f "$TLS_DIR/state.json" ]] && break; kill -0 "$TLS_PID"; sleep 0.1; done
  export PEERLOOM_TLS_ORIGIN TEST_RUNNER_PEERLOOM_TLS_ORIGIN
  PEERLOOM_TLS_ORIGIN=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["origin"])' "$TLS_DIR/state.json")
  TEST_RUNNER_PEERLOOM_TLS_ORIGIN="$PEERLOOM_TLS_ORIGIN"
}
verify_tls() {
  python3 - "$TLS_DIR/state.json" "$OUT/phase-$PHASE-tls.json" <<'PY'
import json,sys
state=json.load(open(sys.argv[1]))
assert state['rejected_handshakes'] >= 1 and state['accepted_handshakes'] == 0, '真实自签 TLS 拒绝证据不足'
# No fixture URL, private key, password or payload in diagnostic artifacts.
with open(sys.argv[2], 'x') as out:
    json.dump({k:state[k] for k in ('rejected_handshakes','accepted_handshakes')},out)
PY
}
cd "$OUT/SwiftPackage"
case "$PHASE" in
  all)
    for stage in macos-swift macos-rust-tls ios-simulator ios-device finalize; do "$HERE/scripts/test-native.sh" --stage "$stage"; done
    ;;
  macos-swift)
    start_tls
    run macos-probe-build 300 swift build --product PeerloomStoreProbe
    export PEERLOOM_STORE_PROBE_BIN
    run_capture macos-probe-path 30 swift build --show-bin-path
    PEERLOOM_STORE_PROBE_BIN="$(cat "$OUT/phase-macos-probe-path.stdout")/PeerloomStoreProbe"
    [[ -x "$PEERLOOM_STORE_PROBE_BIN" ]]
    run macos-swift 300 swift test --parallel
    verify_tls
    ;;
  macos-rust-tls)
    cd "$ROOT/src/device-sdk"
    run macos-rust-tls 900 cargo test --locked -p device-core --test tls
    ;;
  ios-simulator)
    start_tls
    RUNTIME=com.apple.CoreSimulator.SimRuntime.iOS-18-5
    TYPE=com.apple.CoreSimulator.SimDeviceType.iPhone-16
    run_capture ios-runtime-list 30 xcrun simctl list runtimes -j
    python3 - "$OUT/phase-ios-runtime-list.stdout" "$RUNTIME" <<'PY'
import json,sys
assert any(v['identifier']==sys.argv[2] and v.get('isAvailable') for v in json.load(open(sys.argv[1]))['runtimes']), '固定 iOS 18.5 runtime 不可用'
PY
    # New unique simulator only; never erase, shut down or delete an existing operator device.
    run_capture ios-create 30 xcrun simctl create "PeerloomValidation-$$" "$TYPE" "$RUNTIME"
    DEVICE=$(python3 - "$OUT/phase-ios-create.stdout" <<'PY'
import pathlib,sys,uuid
print(uuid.UUID(pathlib.Path(sys.argv[1]).read_text().strip()))
PY
)
    printf '%s\n' "$DEVICE" > "$OUT/phase-ios-device-id.txt"
    run ios-boot 30 xcrun simctl boot "$DEVICE"
    run ios-bootstatus 180 xcrun simctl bootstatus "$DEVICE" -b
    run ios-simulator 600 xcodebuild -scheme PeerloomSwift -destination "platform=iOS Simulator,id=$DEVICE" \
      -derivedDataPath "$OUT/DerivedData-simulator" -resultBundlePath "$OUT/iOS模拟器测试.xcresult" \
      CODE_SIGNING_ALLOWED=NO test
    run_capture ios-summary 30 xcrun xcresulttool get test-results summary --path "$OUT/iOS模拟器测试.xcresult"
    cp "$OUT/phase-ios-summary.stdout" "$OUT/iOS测试摘要.json"
    python3 - "$OUT/iOS测试摘要.json" <<'PY'
import json,sys
summary=json.load(open(sys.argv[1]))
assert summary['totalTestCount'] >= 8 and summary['failedTests'] == 0, 'iOS XCTest 未实际执行足够用例或存在失败'
PY
    verify_tls
    ;;
  ios-device)
    # Build ONLY: no signing identity, provisioning profile, deployment or physical-device claim.
    run ios-device 600 xcodebuild -scheme PeerloomSwift -destination 'generic/platform=iOS' \
      -derivedDataPath "$OUT/DerivedData-device" CODE_SIGNING_ALLOWED=NO \
      BUILD_LIBRARY_FOR_DISTRIBUTION=YES build
    ;;
  cleanup)
    if [[ -f "$OUT/phase-ios-device-id.txt" ]]; then
      DEVICE=$(python3 - "$OUT/phase-ios-device-id.txt" <<'PYID'
import pathlib,sys,uuid
print(uuid.UUID(pathlib.Path(sys.argv[1]).read_text().strip()))
PYID
)
    fi
    ;;
  finalize)
    python3 - "$OUT" <<'PY'
import json,sys
from pathlib import Path
out=Path(sys.argv[1])
for phase in ('macos-swift','macos-rust-tls','ios-simulator','ios-device'):
    status=json.loads((out/('phase-'+phase+'.json')).read_text())
    assert status['classification']=='passed' and status['exit_code']==0, '原生阶段未全部通过'
for phase in ('macos-swift','ios-simulator'):
    tls=json.loads((out/('phase-'+phase+'-tls.json')).read_text())
    assert tls['rejected_handshakes']>=1 and tls['accepted_handshakes']==0, '双平台 TLS 证据不足'
summary=json.loads((out/'iOS测试摘要.json').read_text())
assert summary['totalTestCount']>=8 and summary['failedTests']==0
p=out/'构建证据.json'
meta=json.loads(p.read_text())
meta['status']='native-tests-passed'
meta['native_validation']={
    'macos_swift_tests':True, 'macos_isolated_keychain_and_process_cas':True,
    'macos_rust_system_trust_tests':True, 'ios_simulator_xctest':True,
    'macos_ios_untrusted_tls_rejected':True, 'ios_unsigned_device_build':True,
    'physical_device_test':False, 'production_signing_or_deployment':False,
}
p.write_text(json.dumps(meta,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
(out/'原生测试状态.txt').write_text('本次 macOS XCTest/隔离临时 Keychain/跨进程 CAS、macOS/iOS 自签 TLS 负向、iOS 模拟器 XCTest 与 unsigned device build 已通过。\n设备构建不等于真机验证；未进行生产 DP Keychain 签名宿主验证、部署或法律清关。\n')
(out/'发布审查状态.txt').write_text('全部原生阶段通过；设备构建不等于真机验收，未进行生产签名或部署。\nMIT 仅覆盖本项目原代码；第三方仍遵守各自许可，notice/SBOM 不代表法律清关。\n')
PY
    ;;
esac
