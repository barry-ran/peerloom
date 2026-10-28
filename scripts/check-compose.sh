#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
compose=(docker compose -f infra/compose.yaml)
if [ "${1:-}" = --integration ]; then
  compose+=(-f infra/compose.ci.yaml)
fi
"${compose[@]}" config --quiet

# 默认配置不能向主机发布数据库或缓存，网关只允许回环地址。
docker compose -f infra/compose.yaml config --format json | python3 -c '
import json, sys
c = json.load(sys.stdin)
s = c["services"]
assert not s["postgres"].get("ports"), "PostgreSQL must not be published"
assert not s["redis"].get("ports"), "Redis must not be published"
assert all(p.get("host_ip") == "127.0.0.1" for p in s["gateway"]["ports"]), "Gateway must stay loopback-only"
assert s["device-server"]["environment"].get("DATABASE_URL_FILE"), "Use file-mounted DB secret"
'
