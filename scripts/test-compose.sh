#!/usr/bin/env bash
# 仅隔离开发/CI 环境：此脚本创建并最终删除自己的数据库卷。
set +x
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
project="peerloom-test-${RANDOM}-${RANDOM}"
compose=(docker compose -p "$project" -f infra/compose.yaml -f infra/compose.ci.yaml -f infra/compose.ci-relay.yaml)
fixture=""
management_fixture=""
relay_fixture=""
shared_node_active=false
set_shared_node() {
  "${compose[@]}" run --rm -T --quiet-pull --no-deps --entrypoint device-admin device-server \
    relay-set-shared --offline --node-id 88888888-8888-4888-8888-888888888888 \
    --name ci-managed-relay --endpoint 'turn:127.0.0.1:53478?transport=udp' \
    --secret-ref ci-managed-relay "--enabled=$1" > /dev/null
}
with_shared_relay() {
  local result=0
  # Mark before mutation: an interrupted/unknown enable must still be disabled.
  shared_node_active=true
  if set_shared_node true; then :; else return "$?"; fi
  if "$@"; then result=0; else result=$?; fi
  if set_shared_node false; then
    shared_node_active=false
  else
    local disable_status=$?
    if ((result == 0)); then result=$disable_status; fi
  fi
  return "$result"
}
cleanup() {
  result=$?
  trap '' TERM INT
  if "$shared_node_active"; then
    if set_shared_node false; then
      shared_node_active=false
    else
      disable_status=$?
      if ((result == 0)); then result=$disable_status; fi
    fi
  fi
  if [ -n "$fixture" ]; then rm -f -- "$fixture"; fi
  if [ -n "$management_fixture" ]; then rm -rf -- "$management_fixture"; fi
  "${compose[@]}" down --volumes --remove-orphans || result=$?
  if [ -n "$relay_fixture" ]; then rm -rf -- "$relay_fixture"; fi
  return "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
relay_fixture="$(mktemp -d "$PWD/.secrets/relay-fixture.XXXXXX")"
export PEERLOOM_TEST_RELAY_REGISTRY_FILE="$relay_fixture/registry.json"
python3 - "$relay_fixture" <<'REGISTRY'
from pathlib import Path
import json
import secrets
import sys
p = Path(sys.argv[1])
secret = secrets.token_hex(32)
(p / 'shared-secret').write_text(secret)
(p / 'shared-secret').chmod(0o600)
(p / 'registry.json').write_text(json.dumps({'bindings': {'ci-managed-relay': {
    'tenant_id': '', 'secret': secret, 'urls': ['turn:127.0.0.1:53478?transport=udp']}}}))
# Compose bind-secret必须可由容器非root用户读取；父目录0700限制宿主访问。
(p / 'registry.json').chmod(0o444)
REGISTRY
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
)" TEST_REDIS_URL="$(python3 - <<'REDIS'
from pathlib import Path
from urllib.parse import quote
password = Path('.secrets/redis_password').read_text().strip()
print('redis://:' + quote(password, safe='') + '@127.0.0.1:16379/0')
REDIS
)" go -C src/device-server test -tags=integration -race ./...
"${compose[@]}" run --rm migrate --dir /app/infra/migrations down
"${compose[@]}" run --rm migrate --dir /app/infra/migrations up
"${compose[@]}" up -d --wait device-server gateway
"${compose[@]}" exec -T gateway nginx -t
curl --fail --silent --show-error http://127.0.0.1:18080/healthz > /dev/null
curl --fail --silent --show-error http://127.0.0.1:18080/readyz > /dev/null
test "$(curl --silent --show-error -o /dev/null -w '%{http_code}' http://127.0.0.1:18080/metrics)" = 404
# 未认证信令必须通过网关到达服务端并拒绝，而不是落到未知路由。
test "$(curl --silent --show-error -o /dev/null -w '%{http_code}' -H 'Connection: Upgrade' -H 'Upgrade: websocket' http://127.0.0.1:18080/v1/device-signal)" = 401
# 仅本次随机 Compose 项目的临时租户；grant 不进入 stdout、日志或构建产物。
fixture="$(mktemp "$PWD/.secrets/identity-fixture.XXXXXX")"
chmod 600 "$fixture"
"${compose[@]}" run --rm -T --quiet-pull --no-deps --entrypoint device-bootstrap device-server --development > "$fixture"
python3 - "$fixture" <<'FIXTURE'
import json
import sys
try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        data = json.load(stream)
    assert isinstance(data.get("application_id"), str) and data["application_id"]
    assert isinstance(data.get("registration_grant"), str) and data["registration_grant"]
except Exception:
    raise SystemExit("disposable identity fixture validation failed; contents withheld") from None
FIXTURE
(
  cd src/device-sdk
  TEST_IDENTITY_BASE_URL=http://127.0.0.1:18080 TEST_IDENTITY_FIXTURE_FILE="$fixture" \
    cargo test -p device-core --test identity_service --locked -- --ignored --nocapture
)
rm -f -- "$fixture"
fixture=""
# 跨应用、同租户授权 pair：独立fixture，避免复用身份轮换测试的设备。
fixture="$(mktemp "$PWD/.secrets/identity-fixture.XXXXXX")"
chmod 600 "$fixture"
"${compose[@]}" run --rm -T --quiet-pull --no-deps --entrypoint device-bootstrap device-server --development --pair > "$fixture"
python3 - "$fixture" <<'PAIR'
import json
import sys
try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        data = json.load(stream)
    for side in ("source", "target"):
        for key in ("application_id", "device_id", "device_credential", "expires_at"):
            assert isinstance(data[side][key], str) and data[side][key]
except Exception:
    raise SystemExit("disposable pair fixture validation failed; contents withheld") from None
PAIR
(
  cd src/device-sdk
  TEST_IDENTITY_BASE_URL=http://127.0.0.1:18080 TEST_SIGNAL_FIXTURE_FILE="$fixture" \
    cargo test -p device-core --test authorized_pair --locked -- --ignored --nocapture
)
rm -f -- "$fixture"
fixture=""
# facade 验证使用第三份新pair，不能复用已授权/关闭的会话设备。
fixture="$(mktemp "$PWD/.secrets/identity-fixture.XXXXXX")"
chmod 600 "$fixture"
"${compose[@]}" run --rm -T --quiet-pull --no-deps --entrypoint device-bootstrap device-server --development --pair > "$fixture"
python3 - "$fixture" <<'PAIR'
import json
import sys
try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        data = json.load(stream)
    for side in ("source", "target"):
        for key in ("application_id", "device_id", "device_credential", "expires_at"):
            assert isinstance(data[side][key], str) and data[side][key]
except Exception:
    raise SystemExit("disposable pair fixture validation failed; contents withheld") from None
PAIR
(
  cd src/device-sdk
  TEST_IDENTITY_BASE_URL=http://127.0.0.1:18080 TEST_SIGNAL_FIXTURE_FILE="$fixture" \
    cargo test -p device-core --test sdk_service --locked -- --ignored --nocapture
)
rm -f -- "$fixture"
fixture=""
# 管理API仅针对本脚本的隔离数据库：离线建两租户及只读key，不修改真实环境。
management_fixture="$(mktemp -d "$PWD/.secrets/management-fixture.XXXXXX")"
"${compose[@]}" run --rm -T --quiet-pull --no-deps --entrypoint device-admin device-server \
  bootstrap --offline --tenant-name ci-management --scope admin > "$management_fixture/admin.json"
"${compose[@]}" run --rm -T --quiet-pull --no-deps --entrypoint device-admin device-server \
  bootstrap --offline --tenant-name ci-foreign --scope admin > "$management_fixture/foreign.json"
tenant_id="$(python3 - "$management_fixture/admin.json" <<'TENANT'
import json
import sys
import uuid
try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        print(uuid.UUID(json.load(stream)["tenant_id"]))
except Exception:
    raise SystemExit("invalid management fixture; contents withheld") from None
TENANT
)"
"${compose[@]}" run --rm -T --quiet-pull --no-deps --entrypoint device-admin device-server \
  issue-key --offline --tenant-id "$tenant_id" --scope read > "$management_fixture/read.json"
python3 scripts/test-management.py --base-url http://127.0.0.1:18080 \
  --admin-fixture "$management_fixture/admin.json" \
  --foreign-admin-fixture "$management_fixture/foreign.json" \
  --read-fixture "$management_fixture/read.json" \
  --pair-output "$management_fixture/pair.json"
# 此pair由管理HTTP授权创建，不依赖开发bootstrap直接插入授权。
(
  cd src/device-sdk
  TEST_IDENTITY_BASE_URL=http://127.0.0.1:18080 TEST_SIGNAL_FIXTURE_FILE="$management_fixture/pair.json" \
    cargo test -p device-core --test sdk_service --locked -- --ignored --nocapture
)
rm -rf -- "$management_fixture"
management_fixture=""
# C ABI服务测试会轮换source凭证，必须再次生成独立pair。
fixture="$(mktemp "$PWD/.secrets/identity-fixture.XXXXXX")"
chmod 600 "$fixture"
"${compose[@]}" run --rm -T --quiet-pull --no-deps --entrypoint device-bootstrap device-server --development --pair > "$fixture"
python3 - "$fixture" <<'PAIR'
import json
import sys
try:
    with open(sys.argv[1], encoding="utf-8") as stream:
        data = json.load(stream)
    for side in ("source", "target"):
        for key in ("application_id", "device_id", "device_credential", "expires_at"):
            assert isinstance(data[side][key], str) and data[side][key]
except Exception:
    raise SystemExit("disposable pair fixture validation failed; contents withheld") from None
PAIR
TEST_IDENTITY_BASE_URL=http://127.0.0.1:18080 TEST_SIGNAL_FIXTURE_FILE="$fixture" \
  python3 src/device-sdk/device-ffi/tests/run-service.py
rm -f -- "$fixture"
fixture=""
# 新pair通过控制面自动取得REST凭证，不能复用已轮换的设备，也不向SDK提供静态TURN秘密。
management_fixture="$(mktemp -d "$PWD/.secrets/management-fixture.XXXXXX")"
"${compose[@]}" run --rm -T --quiet-pull --no-deps --entrypoint device-admin device-server \
  bootstrap --offline --tenant-name ci-managed-lease --scope admin > "$management_fixture/admin.json"
python3 scripts/test-management.py --base-url http://127.0.0.1:18080 \
  --admin-fixture "$management_fixture/admin.json" --pair-output "$management_fixture/pair.json"
fixture="$management_fixture/pair.json"
with_shared_relay ./scripts/test-managed-relay.sh --shared-secret-file "$relay_fixture/shared-secret" \
  --pair-fixture "$fixture" --base-url http://127.0.0.1:18080 \
  --lease-admin-fixture "$management_fixture/admin.json"
rm -f -- "$fixture"
fixture=""
rm -rf -- "$management_fixture"
management_fixture=""
# 独立管理员只作用于此随机 Compose 项目；HTTP 创建 fresh reset/recovery pairs。
management_fixture="$(mktemp -d "$PWD/.secrets/management-fixture.XXXXXX")"
"${compose[@]}" run --rm -T --quiet-pull --no-deps --entrypoint device-admin device-server \
  bootstrap --offline --tenant-name ci-lifecycle --scope admin > "$management_fixture/admin.json"
./scripts/test-lifecycle.sh --base-url http://127.0.0.1:18080 \
  --admin-fixture "$management_fixture/admin.json" --shared-secret-file "$relay_fixture/shared-secret"
# Recovery has its own fresh identities and scoped live relay interval. Non-relay
# C/multichannel/control tests must never inherit an enabled, stopped TURN node.
python3 scripts/prepare-lifecycle-fixture.py --base-url http://127.0.0.1:18080 \
  --admin-fixture "$management_fixture/admin.json" --pair-output "$management_fixture/recovery.json"
with_shared_relay ./scripts/test-managed-relay.sh --recovery --base-url http://127.0.0.1:18080 \
  --shared-secret-file "$relay_fixture/shared-secret" --pair-fixture "$management_fixture/recovery.json"
rm -f -- "$management_fixture/recovery.json"
python3 scripts/test-control-recovery.py --project "$project" --base-url http://127.0.0.1:18080 \
  --admin-fixture "$management_fixture/admin.json"
rm -rf -- "$management_fixture"
management_fixture=""
"${compose[@]}" restart device-server
"${compose[@]}" up -d --wait device-server gateway
curl --fail --silent --show-error http://127.0.0.1:18080/readyz > /dev/null
