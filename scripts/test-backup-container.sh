#!/usr/bin/env bash
# Disposable CI-only image. No daemon resources belonging to other projects are removed.
set +x
set -euo pipefail
case "${DOCKER_HOST:-}" in ''|unix:///*) ;; *) echo '仅允许本机 Unix socket Docker daemon' >&2; exit 2 ;; esac
endpoint=$(docker context inspect --format '{{.Endpoints.docker.Host}}')
case "$endpoint" in unix:///*) ;; *) echo '拒绝远程 Docker context' >&2; exit 2 ;; esac
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
nonce=$(python3 -c 'import secrets; print(secrets.token_hex(12))')
image="peerloom-backup-validation:$nonce"
drill="peerloom-backup-drill-$nonce"
evidence="peerloom-backup-evidence-$nonce"
cleanup() {
  # --rm is insufficient when the attached Docker client is interrupted. These
  # unpredictable names belong only to this invocation, including partial runs.
  docker rm -f "$drill" "$evidence" >/dev/null 2>&1 || true
  docker image rm "$image" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
docker build -f infra/tests/backup.Dockerfile -t "$image" .
docker run --name "$drill" --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=512m,mode=1777 "$image"
# Public version evidence only; never archive PGDATA, passwords or logical database content.
docker run --name "$evidence" --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --entrypoint sh "$image" -c 'cat /usr/local/share/peerloom-validation/*'
