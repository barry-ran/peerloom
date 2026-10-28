CREATE TABLE tenant_service_credentials (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    credential_hash bytea NOT NULL UNIQUE CHECK(octet_length(credential_hash)=32),
    scope text NOT NULL CHECK(scope IN('read','admin')),
    label text NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(id,tenant_id)
);

CREATE INDEX tenant_service_credentials_tenant_idx ON tenant_service_credentials(tenant_id,created_at,id);

-- 响应短期加密保存；幂等摘要保留窗口长于秘密响应窗口。
-- response_ciphertext 清理后保留资源标识，不能重新执行同一个变更。
CREATE TABLE management_requests (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    service_credential_id uuid NOT NULL,
    operation text NOT NULL,
    key_hash bytea NOT NULL CHECK(octet_length(key_hash)=32),
    request_hash bytea NOT NULL CHECK(octet_length(request_hash)=32),
    status_code integer NOT NULL CHECK(status_code BETWEEN 200 AND 299),
    resource_id uuid NOT NULL,
    response_nonce bytea CHECK(response_nonce IS NULL OR octet_length(response_nonce)=12),
    response_ciphertext bytea,
    response_expires_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(tenant_id,service_credential_id,operation,key_hash),
    FOREIGN KEY(service_credential_id,tenant_id) REFERENCES tenant_service_credentials(id,tenant_id),
    CHECK(response_expires_at<=expires_at),
    CHECK((response_nonce IS NULL)=(response_ciphertext IS NULL))
);

CREATE INDEX management_requests_expiry_idx ON management_requests(expires_at);
CREATE INDEX management_requests_response_expiry_idx ON management_requests(response_expires_at) WHERE response_ciphertext IS NOT NULL;

CREATE INDEX applications_management_page_idx ON applications(tenant_id,created_at DESC,id DESC);
CREATE INDEX devices_management_page_idx ON devices(tenant_id,created_at DESC,id DESC);
CREATE INDEX devices_management_app_page_idx ON devices(tenant_id,application_id,created_at DESC,id DESC);
CREATE INDEX grants_management_page_idx ON connection_grants(tenant_id,created_at DESC,id DESC);
CREATE INDEX sessions_management_page_idx ON sessions(tenant_id,created_at DESC,id DESC);
CREATE INDEX audit_management_page_idx ON audit_events(tenant_id,id DESC);
