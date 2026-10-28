#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/test-dev-secrets.py
python3 scripts/test-compose-script.py
python3 scripts/test-turn-script.py
python3 scripts/test_contracts.py
python3 scripts/test-package-third-party.py
(
  cd src/device-server
  test -z "$(gofmt -l .)"
  go vet ./...
  go test -race ./...
)
(
  cd src/device-sdk
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets --locked -- -D warnings
  cargo test --workspace --locked
)

# Linux C ABI真实链接生命周期及C++头文件兼容性。
./src/device-sdk/device-ffi/tests/run-c.sh
