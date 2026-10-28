#!/usr/bin/env bash
# CI only: own child PID + explicit serial; never mutate another emulator/device.
set -euo pipefail
page=${1:?expected page bytes}
image=${2:?SDK image package}
case "$page" in
  4096) port=5580 ;;
  16384) port=5582 ;;
  *) echo 'unsupported page size' >&2; exit 1 ;;
esac
root=$(cd "$(dirname "$0")/../../.." && pwd)
export ANDROID_SERIAL="emulator-$port"
export PEERLOOM_AVD_NAME="peerloom-ci-$page"
export ANDROID_AVD_HOME="${RUNNER_TEMP:?CI runner required}/peerloom-avd-$page"
# Reject collisions before creating an AVD or launching a process.
if adb devices | awk 'NR>1 {print $1}' | grep -Fxq "$ANDROID_SERIAL"; then
  echo 'refuse existing emulator serial' >&2
  exit 1
fi
python3 - "$port" <<'PY'
import socket, sys
sockets = []
try:
    for port in (int(sys.argv[1]), int(sys.argv[1]) + 1):
        sock = socket.socket()
        sockets.append(sock)
        sock.bind(("127.0.0.1", port))
finally:
    for sock in sockets:
        sock.close()
PY
test ! -e "$ANDROID_AVD_HOME/$PEERLOOM_AVD_NAME.avd"
test ! -e "$ANDROID_AVD_HOME/$PEERLOOM_AVD_NAME.ini"
mkdir -p "$ANDROID_AVD_HOME"
echo no | avdmanager create avd -n "$PEERLOOM_AVD_NAME" -k "$image"
emulator -avd "$PEERLOOM_AVD_NAME" -port "$port" -no-window -no-audio -no-boot-anim -no-snapshot -wipe-data \
  -gpu swiftshader_indirect -memory 2048 -cores 2 > "$RUNNER_TEMP/emulator-$page.log" 2>&1 &
pid=$!
adb_owned() { command adb -s "$ANDROID_SERIAL" "$@"; }
owned_avd() { [[ $(timeout 5 adb -s "$ANDROID_SERIAL" emu avd name 2>/dev/null | tr -d '\r' | head -n 1) == "$PEERLOOM_AVD_NAME" ]]; }
cleanup() {
  # Never issue emu kill to a foreign serial, even after a launch/bind failure.
  if kill -0 "$pid" 2>/dev/null; then
    if owned_avd; then timeout 5 adb -s "$ANDROID_SERIAL" emu kill >/dev/null 2>&1 || true; fi
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 50); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.1
    done
    kill -KILL "$pid" 2>/dev/null || true
  fi
  wait "$pid" 2>/dev/null || true
}
trap cleanup EXIT
timeout 240 adb -s "$ANDROID_SERIAL" wait-for-device
booted=0
for _ in $(seq 1 240); do
  if [[ $(adb_owned shell getprop sys.boot_completed 2>/dev/null | tr -d '\r') == 1 ]]; then booted=1; break; fi
  kill -0 "$pid" || { echo 'emulator terminated before boot' >&2; exit 1; }
  sleep 1
done
test "$booted" = 1
owned_avd || { echo 'refuse foreign emulator identity' >&2; exit 1; }
test "$(adb_owned shell getconf PAGE_SIZE | tr -d '\r')" = "$page"
adb_owned shell input keyevent 82
adb_owned install -r "$root/dist/android/library-debug-androidTest.apk"
"$root/bindings/android/scripts/run-instrumentation.sh"
