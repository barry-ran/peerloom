#!/usr/bin/env bash
# MIT — Copyright (c) 2026 Peerloom contributors.
set -euo pipefail
[[ $(uname -s) == Darwin ]] || { echo '需要真实 macOS/Xcode；Linux 不生成假 XCFramework' >&2; exit 2; }
: "${PEERLOOM_REPO_ROOT:?设置包含锁定 Cargo 与规范 C 头的仓库根目录}"
: "${PEERLOOM_APPLE_OUTPUT:?设置不存在的输出目录}"
export DEVELOPER_DIR=${DEVELOPER_DIR:-/Applications/Xcode_16.4.app/Contents/Developer}
[[ $(xcodebuild -version) == $'Xcode 16.4\nBuild version 16F6' ]] || { echo '固定 Xcode 16.4/16F6 不匹配' >&2; exit 2; }
[[ $(rustc --version) == rustc\ 1.99.1\ * ]] || { echo '需要固定 Rust 1.99.1' >&2; exit 2; }
[[ ! -e "$PEERLOOM_APPLE_OUTPUT" && ! -L "$PEERLOOM_APPLE_OUTPUT" ]] || { echo '拒绝覆盖 Apple 输出' >&2; exit 2; }
ROOT=$(cd "$PEERLOOM_REPO_ROOT" && pwd)
HERE=$(cd "$(dirname "$0")/.." && pwd)
HEADER="$ROOT/src/device-sdk/device-ffi/include/device_sdk.h"
grep -q 'dp_connection_is_valid' "$HEADER" || { echo '规范 C ABI 缺少只读连接有效性查询，请先整合已审接口' >&2; exit 2; }
TARGETS=(aarch64-apple-darwin x86_64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios)
installed=$(rustup target list --installed)
for target in "${TARGETS[@]}"; do
  grep -qx "$target" <<< "$installed" || { echo "缺少已批准目标 $target；脚本不会自动下载工具链" >&2; exit 2; }
done
mkdir -m 700 "$PEERLOOM_APPLE_OUTPUT"
OUT=$(cd "$PEERLOOM_APPLE_OUTPUT" && pwd)
export CARGO_TARGET_DIR="$OUT/cargo"
export IPHONEOS_DEPLOYMENT_TARGET=15.0 MACOSX_DEPLOYMENT_TARGET=12.0
features=()
if [[ -n ${PEERLOOM_CARGO_FEATURES:-} ]]; then
  [[ "$PEERLOOM_CARGO_FEATURES" =~ ^[a-zA-Z0-9_,-]+$ ]] || exit 2
  features=(--features "$PEERLOOM_CARGO_FEATURES")
fi
for target in "${TARGETS[@]}"; do
  case "$target" in
    *-darwin) sdk=macosx ;;
    aarch64-apple-ios) sdk=iphoneos ;;
    *) sdk=iphonesimulator ;;
  esac
  export SDKROOT
  SDKROOT=$(xcrun --sdk "$sdk" --show-sdk-path)
  (cd "$ROOT/src/device-sdk" && cargo build --locked --release -p device-ffi --target "$target" "${features[@]}")
done
unset SDKROOT
mkdir -p "$OUT/headers" "$OUT/macos" "$OUT/ios-device" "$OUT/ios-simulator"
cp "$HEADER" "$OUT/headers/device_sdk.h"
cat > "$OUT/headers/module.modulemap" <<'MAP'
module CPeerloom {
    header "device_sdk.h"
    export *
}
MAP
# Only architectures of the SAME platform are combined. Device/simulator never share a fat archive.
xcrun lipo -create "$CARGO_TARGET_DIR/aarch64-apple-darwin/release/libdevice_ffi.a" "$CARGO_TARGET_DIR/x86_64-apple-darwin/release/libdevice_ffi.a" -output "$OUT/macos/libdevice_ffi.a"
xcrun lipo -create "$CARGO_TARGET_DIR/aarch64-apple-ios-sim/release/libdevice_ffi.a" "$CARGO_TARGET_DIR/x86_64-apple-ios/release/libdevice_ffi.a" -output "$OUT/ios-simulator/libdevice_ffi.a"
cp "$CARGO_TARGET_DIR/aarch64-apple-ios/release/libdevice_ffi.a" "$OUT/ios-device/libdevice_ffi.a"
mkdir -p "$OUT/SwiftPackage/Artifacts"
xcodebuild -create-xcframework \
  -library "$OUT/macos/libdevice_ffi.a" -headers "$OUT/headers" \
  -library "$OUT/ios-device/libdevice_ffi.a" -headers "$OUT/headers" \
  -library "$OUT/ios-simulator/libdevice_ffi.a" -headers "$OUT/headers" \
  -output "$OUT/SwiftPackage/Artifacts/CPeerloom.xcframework"
cp "$HERE/Package.swift" "$OUT/SwiftPackage/Package.swift"
cp -R "$HERE/Sources" "$HERE/Tests" "$OUT/SwiftPackage/"
cp "$ROOT/LICENSE" "$OUT/LICENSE"
python3 "$HERE/scripts/verify-xcframework.py" "$OUT/SwiftPackage/Artifacts/CPeerloom.xcframework" "$HEADER"
python3 - "$OUT" "$ROOT" <<'PY'
import hashlib,json,os,subprocess,sys
from pathlib import Path
out,root=map(Path,sys.argv[1:])
meta={'status':'built-not-native-tested','xcode':'16.4','xcode_build':'16F6','rust':'1.99.1',
      'runner_image_version':os.environ.get('ImageVersion','local-unrecorded'),
      'sdk_versions':{sdk:subprocess.check_output(['xcrun','--sdk',sdk,'--show-sdk-version'],text=True).strip() for sdk in ['macosx','iphoneos','iphonesimulator']},
      'cargo_lock_sha256':hashlib.sha256((root/'src/device-sdk/Cargo.lock').read_bytes()).hexdigest(),
      'device_build_is_not_physical_device_validation':True}
(out/'构建证据.json').write_text(json.dumps(meta,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
PY
if [[ -d "$ROOT/dist/third-party" ]]; then cp -R "$ROOT/dist/third-party" "$OUT/第三方证据"; fi
printf '%s\n' '原生测试未运行：必须运行 test-native.sh。设备构建不等于真机验收。' 'MIT 仅覆盖本项目原代码；第三方仍遵守各自许可，现有 notice/SBOM 不代表法律清关。' > "$OUT/发布审查状态.txt"
echo 'XCFramework 构建完成；原生验收尚需独立执行'
