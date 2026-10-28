#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$root/dist"
(
  cd "$root/src/device-server"
  for target in linux/amd64 linux/arm64 darwin/arm64 windows/amd64; do
    os="${target%/*}"
    arch="${target#*/}"
    suffix=""
    if [ "$os" = windows ]; then suffix=.exe; fi
    mkdir -p "$root/dist/$os-$arch"
    for binary in device-server device-migrate device-bootstrap device-admin; do
      CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -o "$root/dist/$os-$arch/$binary$suffix" "./cmd/$binary"
    done
  done
)
(
  cd "$root/src/device-sdk"
  cargo build --workspace --release --locked
  mkdir -p "$root/dist/rust-host"
  # 仅当前构建主机 Rust 库，不冒充五端 SDK 安装包或稳定 C ABI。
  cp target/release/libdevice_core.rlib target/release/libdevice_protocol.rlib target/release/libdevice_transport_webrtc.rlib target/release/libdevice_storage.rlib "$root/dist/rust-host/"
)
