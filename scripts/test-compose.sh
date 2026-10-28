#!/usr/bin/env bash
# 仅隔离开发/CI 环境：此脚本创建并最终删除自己的数据库卷。
set +x
set -euo pipefail
cd "$(dirname "$0")/.."
project="peerloom-test-${RANDOM}-${RANDOM}"
compose=(docker compose -p "$project" -f infra/compose.yaml -f infra/compose.ci.yaml)
fixture=""
cleanup() {
  if [ -n "$fixture" ]; then rm -f -- "$fixture"; fi
  "${compose[@]}" down --volumes --remove-orphans
}
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
"${compose[@]}" restart device-server
"${compose[@]}" up -d --wait device-server gateway
curl --fail --silent --show-error http://127.0.0.1:18080/readyz > /dev/null
