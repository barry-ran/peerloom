-- 降级前关闭依赖新租约语义的会话，避免旧版本把它们当无限授权。
UPDATE sessions SET state='closed',close_reason='LEASE_DOWNGRADE',closed_at=clock_timestamp() WHERE state<>'closed';
DROP INDEX sessions_request_key_idx,sessions_source_active_idx,sessions_target_active_idx,sessions_grant_active_idx;
ALTER TABLE sessions DROP CONSTRAINT sessions_active_lease_check,
    DROP COLUMN request_id,DROP COLUMN source_lease_expires_at,DROP COLUMN target_lease_expires_at,
    DROP COLUMN lease_generation,DROP COLUMN source_connected,DROP COLUMN target_connected,
    DROP COLUMN source_offer_seen,DROP COLUMN target_answer_seen;
