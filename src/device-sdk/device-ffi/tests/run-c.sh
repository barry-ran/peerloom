#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
cargo build --manifest-path "$root/Cargo.toml" --locked -p device-ffi
# Respect CARGO_TARGET_DIR; no generated binaries inside tracked source directories.
target=${CARGO_TARGET_DIR:-"$root/target"}
mkdir -p "$target/ffi-tests"
cc -std=c11 -Wall -Wextra -Werror -pedantic -pthread -I"$root/device-ffi/include" \
  "$root/device-ffi/tests/lifecycle.c" -L"$target/debug" -ldevice_ffi \
  -Wl,-rpath,"$target/debug" -o "$target/ffi-tests/lifecycle"
printf '#include "device_sdk.h"\nstatic_assert(sizeof(dp_event::request_id)==8);\n' | \
  c++ -std=c++17 -Wall -Wextra -Werror -pedantic -I"$root/device-ffi/include" -x c++ -fsyntax-only -
"$target/ffi-tests/lifecycle"
