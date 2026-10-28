-- 已存在的旧会话没有可验证租约；迁移时关闭，而不是默认为永久授权。
UPDATE sessions SET state='closed',close_reason='LEASE_MIGRATION',closed_at=clock_timestamp() WHERE state<>'closed';

ALTER TABLE sessions
    ADD COLUMN request_id uuid,
    ADD COLUMN source_lease_expires_at timestamptz,
    ADD COLUMN target_lease_expires_at timestamptz,
    ADD COLUMN lease_generation bigint NOT NULL DEFAULT 0 CHECK(lease_generation>=0),
    ADD COLUMN source_connected boolean NOT NULL DEFAULT false,
    ADD COLUMN target_connected boolean NOT NULL DEFAULT false,
    ADD COLUMN source_offer_seen boolean NOT NULL DEFAULT false,
    ADD COLUMN target_answer_seen boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT sessions_active_lease_check CHECK (
        state IN('requested','authorizing','closed') OR
        (source_lease_expires_at IS NOT NULL AND target_lease_expires_at IS NOT NULL AND lease_generation>0)
    );

CREATE UNIQUE INDEX sessions_request_key_idx ON sessions(tenant_id,source_device_id,request_id) WHERE request_id IS NOT NULL;
CREATE INDEX sessions_source_active_idx ON sessions(tenant_id,source_device_id) WHERE state<>'closed';
CREATE INDEX sessions_target_active_idx ON sessions(tenant_id,target_device_id) WHERE state<>'closed';
CREATE INDEX sessions_grant_active_idx ON sessions(tenant_id,grant_id) WHERE state<>'closed';
