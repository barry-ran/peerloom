#!/usr/bin/env bash
# 仅已有隔离 Compose 的 loopback 服务；两份独立身份，失败也清理秘密。
set +x
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
base_url=''
admin=''
secret=''
while (($#)); do
  case "$1" in
    --base-url) base_url=${2:?}; shift 2 ;;
    --admin-fixture) admin=${2:?}; shift 2 ;;
    --shared-secret-file) secret=${2:?}; shift 2 ;;
    *) echo 'unsupported lifecycle test argument' >&2; exit 2 ;;
  esac
done
[[ -n "$base_url" && -n "$admin" && -n "$secret" ]]
fixture=$(mktemp -d "${TMPDIR:-/tmp}/peerloom-lifecycle.XXXXXXXX")
cleanup() {
  result=$?
  rm -rf -- "$fixture"
  return "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Three independent all-pass pressure rounds, never retry an admitted operation.
# A failed round exits immediately under set -e; original C 45s bound is unchanged.
for round in 1 2 3; do
  echo "C ABI pressure/reset round=$round/3"
  python3 scripts/prepare-lifecycle-fixture.py --base-url "$base_url" \
    --admin-fixture "$admin" --pair-output "$fixture/reset-$round.json" --direct-reset
  TEST_IDENTITY_BASE_URL="$base_url" TEST_SIGNAL_FIXTURE_FILE="$fixture/reset-$round.json" \
    python3 src/device-sdk/device-ffi/tests/run-service.py
  rm -f -- "$fixture/reset-$round.json"
done
python3 scripts/prepare-lifecycle-fixture.py --base-url "$base_url" \
  --admin-fixture "$admin" --pair-output "$fixture/recovery.json"
./scripts/test-managed-relay.sh --recovery --base-url "$base_url" \
  --shared-secret-file "$secret" --pair-fixture "$fixture/recovery.json"

rm -f -- "$fixture/recovery.json"
python3 scripts/prepare-multiconnection-fixture.py --base-url "$base_url" \
  --admin-fixture "$admin" --output "$fixture/multiconnection.json"
TEST_IDENTITY_BASE_URL="$base_url" TEST_MULTICONNECTION_FIXTURE_FILE="$fixture/multiconnection.json" \
  TEST_LEASE_ADMIN_FIXTURE="$admin" \
  cargo test --manifest-path src/device-sdk/Cargo.toml -p device-core --test sdk_multiconnection \
    --locked -- --ignored --nocapture

rm -f -- "$fixture/multiconnection.json"
python3 scripts/prepare-multiconnection-fixture.py --base-url "$base_url" \
  --admin-fixture "$admin" --output "$fixture/channels.json"
TEST_IDENTITY_BASE_URL="$base_url" TEST_MULTICONNECTION_FIXTURE_FILE="$fixture/channels.json" \
  cargo test --manifest-path src/device-sdk/Cargo.toml -p device-core --test sdk_channels \
    --locked -- --ignored --nocapture

rm -f -- "$fixture/channels.json"
python3 scripts/prepare-multiconnection-fixture.py --base-url "$base_url" \
  --admin-fixture "$admin" --output "$fixture/ffi-channels.json"
TEST_IDENTITY_BASE_URL="$base_url" TEST_MULTICONNECTION_FIXTURE_FILE="$fixture/ffi-channels.json" \
  python3 src/device-sdk/device-ffi/tests/run-channels.py
