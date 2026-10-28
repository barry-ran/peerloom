-- 敏感重试结果仅以应用层 AES-GCM 密文短期保存，凭证本体仍仅存哈希。
ALTER TABLE device_credentials ADD COLUMN rotated_at timestamptz;

CREATE TABLE identity_replays (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    operation text NOT NULL CHECK(operation IN('registration','refresh')),
    principal_scope text NOT NULL,
    key_hash bytea NOT NULL,
    request_hash bytea NOT NULL,
    nonce bytea NOT NULL,
    ciphertext bytea NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(tenant_id,operation,principal_scope,key_hash),
    CHECK(octet_length(key_hash)=32),
    CHECK(octet_length(request_hash)=32),
    CHECK(octet_length(nonce)=12)
);

CREATE INDEX identity_replays_expiry_idx ON identity_replays(expires_at);
