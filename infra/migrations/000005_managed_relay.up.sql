ALTER TABLE relay_nodes ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK(revision>0);
CREATE INDEX relay_nodes_management_page_idx ON relay_nodes(tenant_id,created_at DESC,id DESC);
CREATE UNIQUE INDEX sessions_tenant_identity_idx ON sessions(id,tenant_id);

-- 只保存随机用户名和到期，不保存 TURN password；经重新授权后使用运维密钥派生。
CREATE TABLE relay_issuances (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    device_id uuid NOT NULL,
    session_id uuid NOT NULL,
    node_id uuid NOT NULL REFERENCES relay_nodes(id),
    negotiation_generation integer NOT NULL CHECK(negotiation_generation=1),
    issuance_generation bigserial CHECK(issuance_generation>0),
    node_revision bigint NOT NULL CHECK(node_revision>0),
    secret_ref text NOT NULL,
    username text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(tenant_id,device_id,session_id,node_id,negotiation_generation),
    FOREIGN KEY(device_id,tenant_id) REFERENCES devices(id,tenant_id),
    FOREIGN KEY(session_id,tenant_id) REFERENCES sessions(id,tenant_id),
    CHECK(expires_at>created_at),
    CHECK(length(username) BETWEEN 24 AND 64)
);
CREATE INDEX relay_issuances_expiry_idx ON relay_issuances(expires_at);

-- 固定窗口限额持久化，不能因 Redis 重启或回执替换清零。
CREATE TABLE relay_issuance_windows (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    scope text NOT NULL CHECK(scope IN('tenant','device','session')),
    subject_id uuid NOT NULL,
    window_start timestamptz NOT NULL,
    issued integer NOT NULL CHECK(issued>0),
    PRIMARY KEY(tenant_id,scope,subject_id,window_start)
);
CREATE INDEX relay_issuance_windows_cleanup_idx ON relay_issuance_windows(window_start);
