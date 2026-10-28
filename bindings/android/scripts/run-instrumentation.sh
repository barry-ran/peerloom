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
run() {
  local name=$1
  local log="$out/${name//\#/-}.txt"
  adb_owned shell am instrument -w -r -e class "io.peerloom.sdk.$name" "$package/androidx.test.runner.AndroidJUnitRunner" | tee "$log"
  ! grep -Eq 'FAILURES!!!|INSTRUMENTATION_FAILED|Process crashed|shortMsg=' "$log"
  grep -Eq 'OK \([1-9][0-9]* tests?\)' "$log"
}
adb_owned shell setprop debug.checkjni 1
test "$(adb_owned shell getprop debug.checkjni | tr -d '\r')" = 1
run LifecycleTest
run StoreTest
run StoreProcessTest
run 'PersistenceTest#writePhase'
adb_owned shell am force-stop "$package"
run 'PersistenceTest#readPhase'
run TlsTest
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
