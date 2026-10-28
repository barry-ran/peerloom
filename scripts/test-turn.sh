#!/usr/bin/env bash
# 仅 Linux 本机/CI 的真实 TURN 验收，不属于默认 Compose 或生产部署。
set +x
set -euo pipefail
cd "$(dirname "$0")/.."
test "$(uname -s)" = Linux
if [ "$(id -u)" = 0 ]; then echo 'TURN test requires a non-root caller' >&2; exit 1; fi
umask 077
fixture="$(mktemp -d "${TMPDIR:-/tmp}/peerloom-turn.XXXXXXXX")"
container="peerloom-turn-$(basename "$fixture")"
image="peerloom-turn-test:$(basename "$fixture")"
cleanup() {
  result=$?
  if [ "$result" -ne 0 ]; then
    # 仅状态字段与脱敏错误类别；禁止docker inspect完整配置/环境或原始日志。
    docker inspect --format 'TURN state={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} runtime_error={{.State.Error}}' "$container" > "$fixture/state.log" 2>/dev/null || true
    docker logs "$container" > "$fixture/diagnostic.log" 2>&1 || true
    python3 - "$fixture" <<'DIAGNOSTIC' || true
from pathlib import Path
import sys
p = Path(sys.argv[1])
text = (p / 'state.log').read_text(errors='replace') + '\n' + (p / 'diagnostic.log').read_text(errors='replace')
for name in ('username', 'password'):
    if (p / name).exists():
        secret = (p / name).read_text()
        if secret:
            text = text.replace(secret, '[redacted]')
# 早退可能没有ERROR级别；保留末尾启动文本，仍完整替换两项随机秘密。
lines = text.splitlines()
for line in lines[-20:]:
    print('TURN diagnostic: ' + line[:500], file=sys.stderr)
DIAGNOSTIC
  fi
  docker rm -f -v "$container" > /dev/null 2>&1 || true
  docker image rm "$image" > /dev/null 2>&1 || true
  rm -rf -- "$fixture"
  return "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
python3 - "$fixture" <<'CONFIG'
from pathlib import Path
import secrets
import sys
p = Path(sys.argv[1])
username = 'test-' + secrets.token_hex(8)
password = secrets.token_urlsafe(32)
(p / 'username').write_text(username)
(p / 'password').write_text(password)
(p / 'turnserver.conf').write_text('''listening-ip=127.0.0.1
relay-ip=127.0.0.1
listening-port=53478
min-port=55000
max-port=55031
lt-cred-mech
realm=peerloom.test
fingerprint
no-tcp
no-tls
no-dtls
no-tcp-relay
no-multicast-peers
# 仅loopback测试例外，禁止复制到生产环境。
allow-loopback-peers
cli=0
relay-threads=1
user-quota=8
total-quota=16
max-bps=1048576
stale-nonce=600
no-software-attribute
log-file=stdout
simple-log
pidfile=/tmp/turnserver.pid
userdb=/tmp/turndb
''' + f'user={username}:{password}\n')
for file in p.iterdir():
    file.chmod(0o600)
CONFIG
# 上游文件带NET_BIND_SERVICE有效能力，cap-drop ALL会使execve拒绝执行。
# 只在无网络构建层创建相同字节、无xattr的新inode；不增加运行期权限。
# stdin Dockerfile没有构建上下文，因此凭证不会进入镜像层或构建缓存。
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
# host network 只用于本脚本；配置明确仅绑定loopback，绝不映射公网端口。
docker run --detach --name "$container" \
  --network host --user "$(id -u):$(id -g)" \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --tmpfs /var/lib/coturn:rw,noexec,nosuid,size=1m \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --pids-limit 64 --memory 128m --cpus 2 --stop-timeout 10 \
  --mount "type=bind,src=$fixture/turnserver.conf,dst=/etc/coturn/turnserver.conf,readonly" \
  --entrypoint /usr/bin/turnserver \
  "$image" \
  -c /etc/coturn/turnserver.conf > /dev/null
# 不打印服务配置/日志；真实STUN响应只作为ready，最终gate依赖真实relay消息。
python3 - <<'READY'
import secrets
import socket
import struct
import time
transaction = secrets.token_bytes(12)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(.2)
    for attempt in range(50):
        sock.sendto(struct.pack('!HHI', 1, 0, 0x2112a442) + transaction, ('127.0.0.1', 53478))
        try:
            data, _ = sock.recvfrom(4096)
        except TimeoutError:
            time.sleep(.1)
            continue
        if data[:2] == b'\x01\x01' and data[8:20] == transaction:
            break
    else:
        raise SystemExit('isolated TURN UDP readiness failed; no secrets logged')
READY
(
  cd src/device-sdk
  TEST_TURN_URL='turn:127.0.0.1:53478?transport=udp' \
  TEST_TURN_USERNAME="$(cat "$fixture/username")" TEST_TURN_CREDENTIAL_FILE="$fixture/password" \
    cargo test -p device-transport-webrtc --test turn_pair --locked -- --ignored --nocapture
)
