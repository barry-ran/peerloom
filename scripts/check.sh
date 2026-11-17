#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/test-script-modes.py
python3 scripts/test-admin-deployment.py
python3 scripts/test-dev-secrets.py
python3 scripts/test-compose-script.py
python3 scripts/test-control-recovery-script.py
python3 scripts/test-lifecycle-script.py
python3 scripts/test-capacity-controller.py
python3 scripts/test-capacity-ci.py
python3 scripts/tests/test_stream_performance_summary.py
python3 scripts/test-multiconnection-fixture.py
python3 scripts/test-managed-relay-script.py
python3 scripts/test-managed-relay-helper.py
python3 scripts/test-turn-script.py
python3 scripts/test-turn-refresh-script.py
python3 scripts/test-checkout-evidence.py
python3 scripts/test-vendored-nix.py
python3 scripts/test_contracts.py
python3 scripts/test-package-third-party.py
python3 scripts/test-package-release.py
python3 scripts/test-release-admin.py
python3 scripts/test-maven-gap-policy.py
python3 scripts/test-license-gap-policy.py
python3 scripts/test-postgres-backup.py
python3 scripts/test-tls-compose-script.py
python3 scripts/test-windows-service-script.py
python3 scripts/test-vendor-evidence.py
python3 scripts/test-vendored-webrtc.py
python3 scripts/test-vendored-rtc-turn.py
python3 scripts/test-vendored-rtc-ice.py
python3 scripts/test-rtc-convey-runner.py
python3 bindings/android/scripts/test-maven-evidence.py
(
  cd src/device-server
  test -z "$(gofmt -l .)"
  go vet ./...
  go test -race ./...
  # 真实TURN到期窗口计时前先编译发行fixture，避免冷编译占用短TTL。
  go test -tags=integration -run '^$' ./internal/relay
)
(
  cd src/device-sdk
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets --locked -- -D warnings
  cargo test --workspace --locked
  # Trickle RFC regressions must run with real Agent delivery counters enabled.
  cargo clippy -p device-core -p device-transport-webrtc --all-targets --features device-core/test-diagnostics --locked -- -D warnings
  cargo test -p device-core --lib --features test-diagnostics --locked
  cargo test --manifest-path ../../third_party/rust/rtc-ice-0.21.1/crate/Cargo.toml --lib --locked --target-dir target/vendor-rtc-ice-tests
  python3 ../../scripts/run-rtc-convey-tests.py
  cargo test -p device-transport-webrtc -p webrtc --lib --features webrtc/runtime-mock --locked trickle_park_wake_regression
  cargo test --manifest-path ../../third_party/rust/rtc-turn-0.21.1/crate/Cargo.toml --lib --locked --target-dir target/vendor-rtc-turn-tests
  if [[ "$(uname -s)" == Linux ]]; then
    # 真实 UDP worker 回归不属于默认单测；只跳过显式性能测量。
    timeout --signal=TERM --kill-after=10s 180s \
      cargo test -p device-core --lib --locked \
      sdk::channels::stream::tests::worker_performance:: -- \
      --ignored --skip sdk_worker_backpressure_performance --nocapture --test-threads=1
  fi
  cargo test -p webrtc --lib --locked peer_connection::driver::turn_flush_regression::core_relay_packet_must_reach_socket_in_same_flush_without_another_wake -- --exact
  cargo test -p webrtc --lib --locked peer_connection::driver::buffered_amount_advisory_regression::
  cargo test -p device-transport-webrtc -p webrtc --lib --features webrtc/runtime-mock --locked turn_read_tail_regression
)

# Linux C ABI真实链接生命周期及C++头文件兼容性。
./src/device-sdk/device-ffi/tests/run-c.sh
