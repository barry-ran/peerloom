#!/usr/bin/env bash
# 与真实控制面联调的私有loopback TURN；不属于默认部署。
set +x
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
[[ $(uname -s) == Linux && $(id -u) != 0 ]]
fixture=$(mktemp -d "${TMPDIR:-/tmp}/peerloom-managed-image.XXXXXXXX")
image="peerloom-managed-turn-test:$(basename "$fixture")"
cleanup() {
  result=$?
  docker image rm "$image" > /dev/null 2>&1 || true
  rm -rf -- "$fixture"
  return "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# 与test-turn.sh相同固定官方二进制，仅新inode移除不需要的filecap。
docker build --network none --tag "$image" - <<'IMAGE'
FROM coturn/coturn:4.18.0-r0@sha256:bbefd3e1fdfdc0d58770fe01b581fd8b00d9f3a5580d00acb77cf719a6bc78e3
USER root
RUN test ! -e /tmp/turnserver-unprivileged \
    && cat /usr/bin/turnserver > /tmp/turnserver-unprivileged \
    && test "$(sha256sum /usr/bin/turnserver | cut -d ' ' -f1)" = "$(sha256sum /tmp/turnserver-unprivileged | cut -d ' ' -f1)" \
    && chmod 0755 /tmp/turnserver-unprivileged \
    && mv /tmp/turnserver-unprivileged /usr/bin/turnserver
USER nobody:nogroup
IMAGE
python3 scripts/test-managed-relay.py --container-image "$image" "$@"
