-- PostgreSQL 18 内置 gen_random_uuid，无需创建或删除共享扩展。

CREATE TABLE tenants (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL,
    status text NOT NULL DEFAULT 'active' CHECK(status IN('active','suspended')),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE applications (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    name text NOT NULL,
    registration_mode text NOT NULL DEFAULT 'grant' CHECK(registration_mode IN('direct','grant','both')),
    require_target_approval boolean NOT NULL DEFAULT false,
    max_connections integer NOT NULL DEFAULT 8 CHECK(max_connections>=0),
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(id,tenant_id)
);

CREATE TABLE devices (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    application_id uuid NOT NULL,
    installation_key_hash bytea NOT NULL,
    platform text NOT NULL CHECK(platform IN('windows','macos','linux','android','ios','web')),
    sdk_version text,
    display_name text,
    metadata jsonb NOT NULL DEFAULT '{}',
    tags jsonb NOT NULL DEFAULT '{}',
    connectable boolean NOT NULL DEFAULT true,
    max_connections integer CHECK(max_connections>=0),
    status text NOT NULL DEFAULT 'active' CHECK(status IN('active','revoked')),
    last_seen_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(id,tenant_id),
    FOREIGN KEY(application_id,tenant_id) REFERENCES applications(id,tenant_id)
);

CREATE INDEX devices_tenant_app_idx ON devices(tenant_id,application_id);

CREATE INDEX devices_tags_gin ON devices USING gin(tags);

CREATE TABLE device_credentials (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    device_id uuid NOT NULL,
    credential_hash bytea NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY(device_id,tenant_id) REFERENCES devices(id,tenant_id)
);

CREATE INDEX credentials_device_idx ON device_credentials(device_id);

CREATE TABLE registration_grants (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    application_id uuid NOT NULL,
    secret_hash bytea NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY(application_id,tenant_id) REFERENCES applications(id,tenant_id)
);

CREATE TABLE connection_grants (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    source_device_id uuid NOT NULL,
    target_device_id uuid NOT NULL,
    expires_at timestamptz NOT NULL,
    expiry_action text NOT NULL DEFAULT 'terminate' CHECK(expiry_action IN('terminate','no_new_connections')),
    max_sessions integer NOT NULL DEFAULT 1 CHECK(max_sessions>0),
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY(source_device_id,tenant_id) REFERENCES devices(id,tenant_id),
    FOREIGN KEY(target_device_id,tenant_id) REFERENCES devices(id,tenant_id),
    CHECK(source_device_id<>target_device_id),
    UNIQUE(id,tenant_id,source_device_id,target_device_id)
);

CREATE INDEX grants_lookup_idx ON connection_grants(tenant_id,source_device_id,target_device_id,expires_at) WHERE revoked_at IS NULL;

CREATE TABLE sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    source_device_id uuid NOT NULL,
    target_device_id uuid NOT NULL,
    grant_id uuid,
    state text NOT NULL CHECK(state IN('requested','authorizing','connecting','connected','reconnecting','closed')),
    path text NOT NULL DEFAULT 'unknown' CHECK(path IN('unknown','direct','relay')),
    close_reason text,
    created_at timestamptz NOT NULL DEFAULT now(),
    connected_at timestamptz,
    closed_at timestamptz,
    FOREIGN KEY(source_device_id,tenant_id) REFERENCES devices(id,tenant_id),
    FOREIGN KEY(target_device_id,tenant_id) REFERENCES devices(id,tenant_id),
    CHECK(source_device_id<>target_device_id),
    -- 当前仅支持显式 grant；无授权依据的会话不能进入连接阶段。
    CHECK(state IN('requested','authorizing','closed') OR grant_id IS NOT NULL),
    FOREIGN KEY(grant_id,tenant_id,source_device_id,target_device_id) REFERENCES connection_grants(id,tenant_id,source_device_id,target_device_id)
);

CREATE INDEX sessions_active_idx ON sessions(tenant_id,state) WHERE state<>'closed';

CREATE TABLE relay_nodes (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid REFERENCES tenants(id),
    name text NOT NULL,
    region text,
    endpoint text NOT NULL,
    secret_ref text,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE webhook_endpoints (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    url text NOT NULL,
    secret_ref text NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id uuid REFERENCES tenants(id),
    actor_type text NOT NULL,
    actor_id text,
    action text NOT NULL,
    resource_type text,
    resource_id text,
    details jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_tenant_time_idx ON audit_events(tenant_id,created_at DESC);

-- 在线状态来自 Redis 租约，数据库不保存权威 online 布尔值。

-- 并发会话额度必须由服务事务层原子占用与释放。
