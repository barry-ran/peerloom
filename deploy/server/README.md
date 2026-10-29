# Peerloom 服务端运行包

本说明适用于 `server-linux-amd64` 的解压后安装载荷，不是 SDK 安装说明。v0.1.1 拆包须通过对应版本完整 CI 并正式发布后下载使用；本说明本身不证明已发布或已部署生产环境。v0.1.0 已发布资产不覆盖。

## 包含什么、仍需什么

- `bin/`：`device-server`、`device-migrate`、`device-bootstrap`、`device-admin`、`device-admin-user`，均为 Linux amd64 预编译程序。管理后台 HTML/CSS/JavaScript 内嵌在 `device-server`。
- `infra/migrations/`：版本 1–10 的 10 对 up/down SQL。
- `deploy/`：仅复制预编译程序的运行时 Dockerfile、Compose、TLS 覆盖、网关配置及秘密初始化脚本。
- `docs/部署指南.md`、版本元数据、许可证据与完整校验清单。

宿主需要 Linux amd64、Docker Engine、Docker Compose（TLS 覆盖需 ≥2.24.4）、Python 3.10+ 标准库，以及解压/校验工具。**不需要项目源码、Go、Rust、Cargo、Node 或 npm。** 构建运行镜像仍需联网拉取文件中已固定版本与摘要的 Alpine/PostgreSQL/Redis/nginx 镜像；这不是全部镜像的离线交付包。不要擅自将固定镜像改成 `latest`。

仅控制面与管理入口随 Compose 启动；TURN 需独立部署、配置网络/证书及登记运营者 secret 引用。包内没有生产 TURN 默认主密钥或完整公网配置。

## 解压与校验

先从正式 Release 核对外层 ZIP 的版本、摘要与来源。外层 ZIP 仅供封装；**安装使用其中的 `peerloom-server-linux-amd64.tar.gz`**，它保留 Unix 可执行位，不使用 ZIP 松散文件替代程序。

```sh
# 在一个全新目录操作；路径以实际下载文件为准，不覆盖已有部署。
mkdir peerloom-server-0.1.1
cd peerloom-server-0.1.1
unzip ../peerloom-server-v0.1.1-linux-amd64.zip -d archive
mkdir runtime
tar -xzf archive/peerloom-server-linux-amd64.tar.gz -C runtime
cd runtime
sha256sum -c SHA256SUMS
```

以下命令全部在这个 `runtime` 包根执行。`release-metadata.json` 必须标明正确版本/提交、`platform=server-linux-amd64`、`product=server`；校验和只证明字节一致，不替代可信下载来源或签名。

## 首次启动：仅本机 HTTP

```sh
python3 deploy/init-private.py
docker compose -f deploy/compose.yaml config --quiet
docker compose -f deploy/compose.yaml build
docker compose -f deploy/compose.yaml up -d --wait postgres redis
docker compose -f deploy/compose.yaml run --rm migrate
docker compose -f deploy/compose.yaml up -d --wait device-server gateway
curl --fail http://127.0.0.1:18080/readyz
```

初始化只新建 `.secrets`，不生成账户或 `.env`、不启动服务。已有同名目录/文件/符号链接、路径或权限不安全时拒绝；中途失败保留本次目录供运维核对，不能靠删除后重试恢复已有数据库。**不要删除秘密后复用旧数据库卷。**

新 `.secrets` 父目录为 0700，授权单文件为 0444，并只挂载给需要它的容器。父目录阻止其他宿主 UID 遍历；单文件只读权限用于 Compose bind-secret 的非 root 容器兼容，不表示可放入公开目录。Docker daemon、宿主 root 及获授权挂载容器属于信任边界。运行时镜像构建上下文仅允许 5 个程序及 18 个 SQL，不复制 secrets。

默认端口仅 `127.0.0.1:18080`。PostgreSQL/Redis 不发布宿主端口，网关拒绝 `/metrics`；管理后台默认关闭，没有默认管理员。只有 `device-server` 另接独立 `egress` 网络，用于策略允许的 HTTPS Webhook 等出站；不会新增宿主监听端口，PostgreSQL/Redis/迁移仍只在内部网络。出口网络不绕过 Webhook 的 SSRF、DNS、重定向和授权检查。明文 HTTP/WS 仅供回环开发，不能把端口改成公网绑定后就当生产部署。

## 显式创建租户与管理员

以下是有数据库操作权限的运维者动作，不是匿名注册流程。`device-admin bootstrap` 创建**新租户**并签发短期 scoped 后端密钥；已有租户不要重复 bootstrap。输出含秘密，禁用 shell tracing，保存到新建私有目录，不用 `tee` 或 CI 日志。

```bash
set -euo pipefail
set +x
umask 077
mkdir -m 700 .operator
( set -C
  docker compose -f deploy/compose.yaml --profile tools run --rm -T \
    --entrypoint device-admin migrate bootstrap --offline \
    --tenant-name '我的租户' --scope admin --ttl 24h --label '初始运维' \
    > .operator/tenant-key.json
)
# 只读取非秘密租户 UUID，后端密钥留在私有文件中。
TENANT_ID="$(python3 -c 'import json,uuid; print(uuid.UUID(json.load(open(".operator/tenant-key.json"))["tenant_id"]))')"
IFS= read -r -s -p '新的管理员密码（至少 15 个字符）: ' admin_password
printf '\n'
printf '%s\n' "$admin_password" | docker compose -f deploy/compose.yaml \
  --profile tools run --rm -T --entrypoint device-admin-user migrate \
  create --offline --tenant-id "$TENANT_ID" --username owner \
  --scope admin --password-stdin
unset admin_password
```

失败时先检查命令分类和数据库状态，不盲目重复创建；文件重定向拒绝覆盖不等于远端数据库动作可回滚。已有租户可直接用运维确认的 UUID 创建账户；服务密钥只交可信业务后端，不能放进浏览器或客户端。`device-bootstrap --development` 仅用于开发夹具，不是生产初始化默认命令。

本机开发显式启用浏览器入口：

```sh
export ADMIN_ORIGIN=http://127.0.0.1:18080
export ADMIN_DEVELOPMENT_LOOPBACK=true
docker compose -f deploy/compose.yaml up -d --wait device-server gateway
# 浏览器访问 http://127.0.0.1:18080/admin/
```

账户密码不进入 argv/环境或日志；唯一 Origin、Host、CSRF 与会话安全校验不可关闭。关闭网页入口不等于撤销已有会话，必要时通过离线账户禁用/重置完成撤销。

## HTTPS/WSS：用户证书、仍默认回环

提供 SAN 与访问主机名匹配的完整 PEM 证书链和私钥。原文件须由当前用户拥有，为非符号链接、单硬链接的普通文件，每个不超过 1 MiB；证书不可被组/其他用户写入，私钥必须禁止组/其他用户访问（例如 0600/0400）。祖先路径也会校验。原私钥保持原字节与权限，不为适配非 root 容器而 chmod 原文件。

```sh
python3 deploy/init-private.py --stage-tls \
  --certificate /absolute/private/fullchain.pem \
  --private-key /absolute/private/server.key
export TLS_ADMIN_ORIGIN=https://localhost:18443  # 留空关闭管理后台
# 以下叠加相同项目，不另建数据库卷；已有镜像由前面 build 生成。
docker compose -f deploy/compose.yaml -f deploy/compose.tls.yaml config --quiet
docker compose -f deploy/compose.yaml -f deploy/compose.tls.yaml up -d --wait postgres redis
docker compose -f deploy/compose.yaml -f deploy/compose.tls.yaml run --rm migrate
docker compose -f deploy/compose.yaml -f deploy/compose.tls.yaml up -d --wait device-server gateway
curl --fail --cacert /absolute/private/issuing-ca.pem https://localhost:18443/readyz
```

工具只在新建 `.tls` 0700 私有目录内生成 `certificate.pem` 和 `private-key.pem` 的 0444 只读副本，供 UID65532 的精确 Compose secret 挂载；不改原文件，不输出内容，不安装信任根。TLS 覆盖固定读取这两份副本，不使用 `TLS_CERTIFICATE_FILE` / `TLS_PRIVATE_KEY_FILE` 路径变量。`.tls` 已存在或中途失败时不覆盖、不自动清理；续期需运维在新的安全目录准备副本并保持原项目/数据库卷归属，不能把重新生成数据库秘密当作证书续期。

TLS 覆盖**替换** HTTP 发布端口为 `127.0.0.1:18443`，不同时保留明文入口，并强制关闭管理开发例外。HTTPS 管理会话使用 Secure Cookie；WSS 保持认证。不要使用 `-k` 或安装测试 CA 到宿主信任库。公网监听、DNS、防火墙、受信证书/续期、出口与 TURN 可达性须由运维单独审核，不自动开放公网。

## 保留状态、升级与参考

- `docker compose -f deploy/compose.yaml down` 停服务但保留数据库卷；TLS 部署使用相同两份配置。不要添加 `-v` 作为普通停机/升级步骤。
- Compose 默认项目名为 `peerloom-server`；多实例需显式指定不同项目名。已有部署升级须保持原项目/卷归属并先备份，不能把新目录、旧数据库和新秘密随意组合。
- 不覆盖旧配置或 `.secrets`；在新目录验证新包并人工合并配置，确保数据库及重放密钥连续。down SQL 可能删除数据，不是自动无损回滚。
- [随包部署指南](../docs/部署指南.md) 含网络、备份和运维限制。其标注的源码维护工具不随本包提供，不能把仓库 `make` 当作安装命令。
- 管理/API 与中继接口沿用公开 v0.1.0 文档：[管理服务](https://github.com/barry-ran/peerloom/blob/v0.1.0/docs/管理服务模块.md)、[浏览器管理](https://github.com/barry-ran/peerloom/blob/v0.1.0/docs/浏览器管理模块.md)、[中继配置](https://github.com/barry-ran/peerloom/blob/v0.1.0/docs/中继服务模块.md)。新拆包启动命令以本说明为准，不要求下载旧源码才能运行。
- 随包第三方 evidence 是共同 Cargo/Go 全锁定候选扫描，不是本服务二进制精确链接清单；许可原文、精确缺项和未法务审核状态完整保留。
