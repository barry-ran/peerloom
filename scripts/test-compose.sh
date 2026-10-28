#!/usr/bin/env bash
# 仅隔离开发/CI 环境：此脚本创建并最终删除自己的数据库卷。
set -euo pipefail
cd "$(dirname "$0")/.."
project="peerloom-test-${RANDOM}-${RANDOM}"
compose=(docker compose -p "$project" -f infra/compose.yaml -f infra/compose.ci.yaml)
cleanup() { "${compose[@]}" down --volumes --remove-orphans; }
trap cleanup EXIT
"${compose[@]}" config --quiet
"${compose[@]}" build
"${compose[@]}" up -d --wait postgres redis
"${compose[@]}" run --rm migrate
# 仅打印地址，不输出环境变量、DSN 或秘密。
"${compose[@]}" port postgres 5432
# 凭证只传给当前测试进程，禁止 shell xtrace 和 URL 日志。
TEST_DATABASE_URL="$(python3 - <<'PY'
from pathlib import Path
print(Path('.secrets/database_url').read_text().strip().replace('@postgres:5432/', '@127.0.0.1:15432/'))
PY
)" go -C src/device-server test -tags=integration -race ./...
"${compose[@]}" run --rm migrate --dir /app/infra/migrations down
"${compose[@]}" run --rm migrate --dir /app/infra/migrations up
"${compose[@]}" up -d --wait device-server gateway
curl --fail --silent --show-error http://127.0.0.1:18080/healthz > /dev/null
curl --fail --silent --show-error http://127.0.0.1:18080/readyz > /dev/null
test "$(curl --silent --show-error -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/metrics)" = 404
"${compose[@]}" restart device-server
"${compose[@]}" up -d --wait device-server gateway
curl --fail --silent --show-error http://127.0.0.1:18080/readyz > /dev/null
