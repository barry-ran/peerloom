#!/usr/bin/env bash
# Only an isolated disposable HOME/session bus/keyring; never unlock a real user keyring.
set -euo pipefail
cd "$(dirname "$0")/.."
for tool in dbus-run-session dbus-monitor gdbus gnome-keyring-daemon python3 cargo rustc dpkg-query stdbuf timeout; do
  command -v "$tool" >/dev/null || { echo "missing integration dependency: $tool" >&2; exit 1; }
done
mkdir -p dist/validation
{
  printf 'ImageOS=%s\nImageVersion=%s\n' "${ImageOS:-unknown}" "${ImageVersion:-unknown}"
  uname -srm
  rustc --version
  cargo --version
  gnome-keyring-daemon --version
  dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' dbus dbus-x11 gnome-keyring
} > dist/validation/secret-service-toolchain.txt
manifest="${PEERLOOM_SDK_MANIFEST:-$PWD/src/device-sdk/Cargo.toml}"
binary=$(cargo test --manifest-path "$manifest" -p device-storage --test secret_service --locked --no-run --message-format=json | python3 -c 'import json,sys; artifacts=[j["executable"] for line in sys.stdin if (j:=json.loads(line)).get("reason")=="compiler-artifact" and j.get("executable") and j.get("target",{}).get("name")=="secret_service"]; assert len(artifacts)==1; print(artifacts[0])')
root=$(mktemp -d "${TMPDIR:-/tmp}/peerloom-keyring.XXXXXXXX")
trap 'rm -rf -- "$root"' EXIT
mkdir -m 700 "$root/home" "$root/data" "$root/runtime" "$root/config" "$root/locks"
export HOME="$root/home" XDG_DATA_HOME="$root/data" XDG_RUNTIME_DIR="$root/runtime" XDG_CONFIG_HOME="$root/config"
export PEERLOOM_DISPOSABLE_KEYRING=yes PEERLOOM_TEST_LOCK_DIR="$root/locks" PEERLOOM_KEYRING_TEST_BINARY="$binary" PEERLOOM_KEYRING_TEST_ROOT="$root"
# No daemon or reachable bus: explicit Unavailable, never implicit memory fallback.
DBUS_SESSION_BUS_ADDRESS="unix:path=$root/no-such-bus" "$binary" --ignored --exact unavailable_service_fails_closed
timeout 15s dbus-run-session -- "$binary" --ignored --exact hung_service_has_bounded_shutdown
python3 -c 'import secrets,sys; open(sys.argv[1],"w").write(secrets.token_hex(32))' "$root/password"
chmod 600 "$root/password"
timeout 90s dbus-run-session -- bash -euo pipefail -c '
  daemon=""; monitor=""
  cleanup() { [[ -z "$monitor" ]] || { kill "$monitor" 2>/dev/null || true; wait "$monitor" 2>/dev/null || true; }; [[ -z "$daemon" ]] || { kill "$daemon" 2>/dev/null || true; wait "$daemon" 2>/dev/null || true; }; }
  trap cleanup EXIT
  start_keyring() {
  gnome-keyring-daemon --foreground --components=secrets --unlock < "$PEERLOOM_KEYRING_TEST_ROOT/password" > "$PEERLOOM_KEYRING_TEST_ROOT/daemon.log" 2>&1 & daemon=$!
  ready=0
  for _ in $(seq 1 100); do
    if gdbus call --session --dest org.freedesktop.secrets --object-path /org/freedesktop/secrets --method org.freedesktop.Secret.Service.ReadAlias default 2>/dev/null | grep -q "/org/freedesktop/secrets/collection/"; then ready=1; break; fi
    kill -0 "$daemon" 2>/dev/null || { echo "disposable keyring daemon stopped" >&2; exit 1; }
    sleep .05
  done
  [[ "$ready" == 1 ]] || { echo "disposable keyring did not become ready" >&2; exit 1; }
  }
  start_keyring
  stdbuf -oL dbus-monitor --session "type=method_call,interface=org.freedesktop.Secret.Prompt,member=Prompt" "type=method_call,interface=org.freedesktop.Secret.Service,member=Unlock" > "$PEERLOOM_KEYRING_TEST_ROOT/interaction.log" 2>&1 & monitor=$!
  sleep .1; kill -0 "$monitor"
  "$PEERLOOM_KEYRING_TEST_BINARY" --ignored --exact keyring_write_cas_cancel
  # Restart the daemon as well as the client, with the same encrypted keyring.
  kill "$daemon"; wait "$daemon" || true; daemon=""
  start_keyring
  # New process with the same keyring and lock directory must retain identity.
  "$PEERLOOM_KEYRING_TEST_BINARY" --ignored --exact keyring_restart_reads_same_identity
  "$PEERLOOM_KEYRING_TEST_BINARY" --ignored --exact duplicate_and_missing_items_fail_closed
  "$PEERLOOM_KEYRING_TEST_BINARY" --ignored --exact keyring_locked_fails_without_unlock_or_prompt
  sleep .1
  if grep -Eq "member=(Prompt|Unlock)" "$PEERLOOM_KEYRING_TEST_ROOT/interaction.log"; then echo "unexpected interactive keyring operation" >&2; exit 1; fi
'
# GNOME Keyring on-disk encryption must not contain this synthetic test credential.
if grep -R -a -l 'dev_never_write_this_credential_to_a_plain_file' "$root/data" >/dev/null; then
  echo "test credential found in plaintext persistence" >&2; exit 1
fi
echo 'Secret Service: persistence, restart, cross-instance CAS, cancellation, tombstone, locked/unavailable and no-Prompt checks passed.'
