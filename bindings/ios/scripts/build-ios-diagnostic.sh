#!/usr/bin/env bash
# MIT — Copyright (c) 2026 Peerloom contributors.
# Diagnostic only: one real simulator slice, never a release XCFramework.
set -euo pipefail
[[ $(uname -s) == Darwin && $(uname -m) == arm64 ]] || { echo '需要真实 arm64 Apple runner' >&2; exit 2; }
: "${PEERLOOM_REPO_ROOT:?设置仓库根目录}"
: "${PEERLOOM_APPLE_OUTPUT:?设置独立且不存在的诊断目录}"
export DEVELOPER_DIR=${DEVELOPER_DIR:-/Applications/Xcode_16.4.app/Contents/Developer}
[[ $(xcodebuild -version) == $'Xcode 16.4\nBuild version 16F6' ]] || exit 2
[[ $(rustc --version) == rustc\ 1.99.1\ * ]] || exit 2
[[ ! -e "$PEERLOOM_APPLE_OUTPUT" && ! -L "$PEERLOOM_APPLE_OUTPUT" ]] || { echo '拒绝覆盖诊断输出' >&2; exit 2; }
ROOT=$(cd "$PEERLOOM_REPO_ROOT" && pwd)
HERE=$(cd "$(dirname "$0")/.." && pwd)
HEADER="$ROOT/src/device-sdk/device-ffi/include/device_sdk.h"
grep -q 'dp_connection_is_valid' "$HEADER"
rustup target list --installed | grep -qx aarch64-apple-ios-sim
mkdir -m 700 "$PEERLOOM_APPLE_OUTPUT"
OUT=$(cd "$PEERLOOM_APPLE_OUTPUT" && pwd)
printf '%s\n' '仅诊断：单一 arm64 iOS Simulator slice，不是发布产物或五 slice 验收。' > "$OUT/诊断范围.txt"
export CARGO_TARGET_DIR="$OUT/cargo" IPHONEOS_DEPLOYMENT_TARGET=15.0
export SDKROOT
SDKROOT=$(xcrun --sdk iphonesimulator --show-sdk-path)
cargo_args=(build --locked --release -p device-ffi --target aarch64-apple-ios-sim)
if [[ -n ${PEERLOOM_CARGO_FEATURES:-} ]]; then
  [[ "$PEERLOOM_CARGO_FEATURES" =~ ^[a-zA-Z0-9_,-]+$ ]] || exit 2
  cargo_args+=(--features "$PEERLOOM_CARGO_FEATURES")
fi
(cd "$ROOT/src/device-sdk" && cargo "${cargo_args[@]}")
unset SDKROOT
mkdir -p "$OUT/headers" "$OUT/SwiftPackage/Artifacts"
cp "$HEADER" "$OUT/headers/device_sdk.h"
cat > "$OUT/headers/module.modulemap" <<'MAP'
module CPeerloom {
    header "device_sdk.h"
    export *
}
MAP
xcodebuild -create-xcframework \
  -library "$CARGO_TARGET_DIR/aarch64-apple-ios-sim/release/libdevice_ffi.a" -headers "$OUT/headers" \
  -output "$OUT/SwiftPackage/Artifacts/CPeerloom.xcframework"
cp "$HERE/Package.swift" "$OUT/SwiftPackage/Package.swift"
cp -R "$HERE/Sources" "$HERE/Tests" "$OUT/SwiftPackage/"
python3 - "$OUT/SwiftPackage/Artifacts/CPeerloom.xcframework/Info.plist" <<'PY'
import plistlib,sys
libraries=plistlib.load(open(sys.argv[1],'rb'))['AvailableLibraries']
assert len(libraries)==1
item=libraries[0]
assert item['SupportedPlatform']=='ios' and item['SupportedPlatformVariant']=='simulator'
assert item['SupportedArchitectures']==['arm64']
PY
printf '%s\n' '真实模拟器单 slice 已构建；仍须执行原有全部 iOS XCTest，不能替代完整 native gate。'
