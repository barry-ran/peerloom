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
assert s["device-server"]["environment"].get("REPLAY_KEY_FILE"), "Identity server requires replay key file"
assert s["device-server"]["environment"].get("REDIS_ADDRESS") == "redis:6379", "Redis address mismatch"
assert s["device-server"]["environment"].get("REDIS_PASSWORD_FILE") == "/run/secrets/redis_password", "Redis credential must use mounted file"
assert "redis_password" in {secret["source"] for secret in s["device-server"]["secrets"]}, "Redis credential mount missing"
assert s["device-server"]["depends_on"]["redis"]["condition"] == "service_healthy", "Redis readiness dependency missing"
assert "replay_key" in {secret["source"] for secret in s["device-server"]["secrets"]}, "Replay key mount missing"
for name, service in s.items():
    if name != "device-server":
        assert "replay_key" not in {secret["source"] for secret in service.get("secrets", [])}, "Replay key must stay server-only"
'

# Docker 不为仅连接 internal 网络的服务建立可用主机端口发布。
"${compose[@]}" config --format json | python3 -c '
import json, sys
c = json.load(sys.stdin)
for name, service in c["services"].items():
    if service.get("ports"):
        assert any(not c["networks"][network].get("internal", False) for network in service["networks"]), f"{name}: host ports require a non-internal network"
assert c["networks"]["backend"]["internal"] is True, "Backend isolation must remain enabled"
'
