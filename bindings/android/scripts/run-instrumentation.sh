#!/usr/bin/env bash
set +x
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
serial=${ANDROID_SERIAL:?explicit owned emulator serial required}
avd_name=${PEERLOOM_AVD_NAME:?owned AVD name required}
adb_owned() { command adb -s "$serial" "$@"; }
owned_avd() { [[ $(timeout 5 adb -s "$serial" emu avd name 2>/dev/null | tr -d '\r' | head -n 1) == "$avd_name" ]]; }
owned_avd || { echo 'refuse foreign emulator identity' >&2; exit 1; }
package=io.peerloom.sdk.test
out="$root/dist/android-tests"
mkdir -p "$out"
diagnostics() {
  # Read only this job's emulator. Do not persist raw logcat, credentials or payloads.
  owned_avd || return 0
  timeout 10 adb -s "$serial" logcat -b main -b system -b crash -d -v brief AndroidRuntime:E DEBUG:F libc:F ActivityManager:I PeerloomTestDiag:I '*:S' |
    python3 "$root/bindings/android/scripts/sanitize-diagnostics.py" |
    tee "${1%.txt}-diagnostics.txt" || true
}
instrument_args=()
run() {
  local name=$1
  local label=${2:-$name}
  local log="$out/${label//\#/-}.txt"
  if ! timeout 180 adb -s "$serial" shell am instrument -w -r "${instrument_args[@]}" -e class "io.peerloom.sdk.$name" "$package/androidx.test.runner.AndroidJUnitRunner" | tee "$log"; then
    diagnostics "$log"
    return 1
  fi
  if grep -Eq 'FAILURES!!!|INSTRUMENTATION_FAILED|Process crashed|shortMsg=' "$log" ||
      ! grep -Eq 'OK \([1-9][0-9]* tests?\)' "$log"; then
    diagnostics "$log"
    return 1
  fi
}
adb_owned shell setprop debug.checkjni 1
test "$(adb_owned shell getprop debug.checkjni | tr -d '\r')" = 1
run LifecycleTest
run StoreTest
# A fixed all-pass stability check, not retries: the first failure stops the job.
for attempt in 1 2 3 4 5; do
  run StoreProcessTest "StoreProcessTest-$attempt"
done
run 'PersistenceTest#writePhase'
adb_owned shell am force-stop "$package"
run 'PersistenceTest#readPhase'
run_trusted_tls() (
  set -euo pipefail
  local digest component owner_attempted=0
  digest=$(python3 "$root/bindings/android/scripts/trust-fixture.py" "$root/dist/android/library-debug-androidTest.apk")
  owned_avd || { echo 'refuse foreign emulator trust mutation' >&2; exit 1; }
  test "$(adb_owned shell getprop ro.kernel.qemu | tr -d '\r')" = 1
  component="$package/io.peerloom.sdk.TestCertificateAdmin"
  instrument_args=(-e peerloom_test_ca_sha256 "$digest")
  release_trust() {
    local status=$?
    trap - EXIT
    if [[ "$owner_attempted" = 1 ]]; then
      # CA removal and exact absence verification MUST precede admin removal.
      if ! owned_avd || ! run 'TrustFixtureTest#remove'; then
        echo 'fixture CA cleanup failed; refuse successful CI result' >&2
        exit 1
      fi
      if ! timeout 20 adb -s "$serial" shell dpm remove-active-admin --user 0 "$component" ||
          ! run 'TrustFixtureTest#verifyReleased'; then
        echo 'fixture admin cleanup failed; refuse successful CI result' >&2
        exit 1
      fi
    fi
    exit "$status"
  }
  trap release_trust EXIT
  owner_attempted=1
  timeout 20 adb -s "$serial" shell dpm set-device-owner --user 0 "$component"
  run 'TrustFixtureTest#install'
  run TlsTest
)
run_trusted_tls
project="peerloom-android-${RANDOM}-${RANDOM}"
compose=(docker compose -p "$project" -f "$root/infra/compose.yaml" -f "$root/infra/compose.ci.yaml")
fixture=$(mktemp -d)
chmod 700 "$fixture"
cleanup() {
  if owned_avd; then
    timeout 5 adb -s "$serial" shell "run-as $package rm -f no_backup/pair-fixture.json no_backup/registration-fixture.json" >/dev/null 2>&1 || true
  fi
  "${compose[@]}" down --volumes --remove-orphans
  rm -rf "$fixture"
}
trap cleanup EXIT
cd "$root"
python3 scripts/generate-dev-secrets.py
"${compose[@]}" build
"${compose[@]}" up -d --wait postgres redis
"${compose[@]}" run --rm migrate
"${compose[@]}" up -d --wait device-server gateway
adb_owned reverse tcp:18080 tcp:18080
umask 077
"${compose[@]}" run --rm -T --no-deps --entrypoint device-bootstrap device-server --development > "$fixture/registration-fixture.json"
"${compose[@]}" run --rm -T --no-deps --entrypoint device-bootstrap device-server --development --pair > "$fixture/pair-fixture.json"
for name in registration-fixture.json pair-fixture.json; do
  adb_owned shell "run-as $package sh -c 'umask 077; mkdir -p no_backup; cat > no_backup/$name'" < "$fixture/$name"
done
run RegistrationTest
run ServiceTest
adb_owned shell am force-stop "$package"
run ServiceRestartTest
# Only print CheckJNI failures, not arbitrary device logs or application payloads.
if adb_owned logcat -d | grep -q 'JNI DETECTED ERROR IN APPLICATION'; then
  echo 'CheckJNI detected an error' >&2
  exit 1
fi
