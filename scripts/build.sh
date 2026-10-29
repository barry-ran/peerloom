#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
python3 "$root/scripts/test-package-release.py"
mkdir -p "$root/dist"
(
  cd "$root/src/device-server"
  for target in linux/amd64; do
    os="${target%/*}"
    arch="${target#*/}"
    suffix=""
    if [ "$os" = windows ]; then suffix=.exe; fi
    mkdir -p "$root/dist/$os-$arch"
    for binary in device-server device-migrate device-bootstrap device-admin device-admin-user; do
      CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -o "$root/dist/$os-$arch/$binary$suffix" "./cmd/$binary"
    done
  done
)
(
  cd "$root/src/device-sdk"
  cargo build --workspace --release --locked
  mkdir -p "$root/dist/rust-host"
  # 仅当前构建主机 Rust 库；C ABI产物另放明确Linux目录，不冒充五端SDK。
  cp target/release/libdevice_core.rlib target/release/libdevice_protocol.rlib target/release/libdevice_transport_webrtc.rlib target/release/libdevice_storage.rlib "$root/dist/rust-host/"
)

# 当前仅Linux原生C ABI经过真实C11/C++17测试，不制造其他平台包。
if [ "$(uname -s)" = Linux ]; then
  abi="$root/dist/c-abi-linux-$(uname -m)"
  mkdir -p "$abi/include" "$abi/lib"
  cp "$root/src/device-sdk/target/release/libdevice_ffi.so" "$root/src/device-sdk/target/release/libdevice_ffi.a" "$abi/lib/"
  cp "$root/src/device-sdk/device-ffi/include/device_sdk.h" "$abi/include/"
  cp "$root/LICENSE" "$abi/LICENSE"
  # 直接验证交付的release动态/静态库，不能仅用debug测试冒充产物可链接。
  smoke="$root/src/device-sdk/target/ffi-tests"
  mkdir -p "$smoke"
  cc -std=c11 -Wall -Wextra -Werror -pedantic -pthread -I"$abi/include" \
    "$root/src/device-sdk/device-ffi/tests/lifecycle.c" -L"$abi/lib" -ldevice_ffi \
    -Wl,-rpath,"$abi/lib" -o "$smoke/release-shared-lifecycle"
  "$smoke/release-shared-lifecycle"
  cc -std=c11 -Wall -Wextra -Werror -pedantic -pthread -I"$abi/include" \
    "$root/src/device-sdk/device-ffi/tests/lifecycle.c" "$abi/lib/libdevice_ffi.a" -ldl -lm \
    -o "$smoke/release-static-lifecycle"
  "$smoke/release-static-lifecycle"
  printf '%s\n' 'Linux原生C ABI检查产物；ABI版本见device_sdk.h。不是五端SDK或生产发布承诺。' > "$abi/产物范围.txt"
fi
cp "$root/LICENSE" "$root/dist/LICENSE"
# 只由明确producer补齐status/admin/vendor原文的SHA，未知extra仍拒绝。
python3 "$root/scripts/test-vendored-nix.py"
python3 "$root/scripts/package-third-party.py" --include-build-notices

# 包内 metadata 固定当前提交、项目版本与默认 feature；完整 SHA 覆盖第三方证据。
python3 "$root/scripts/package-release.py" --platform linux-x86_64 --output "$root/dist/release/linux-x86_64"

# 服务部署包独立交付，不把Go工具混入任何SDK包。
python3 "$root/scripts/package-release.py" --platform server-linux-amd64 --output "$root/dist/release/server-linux-amd64"
