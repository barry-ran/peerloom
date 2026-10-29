-- Refuse downgrade while any exclusive authority can still be exercised.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM sessions WHERE target_epoch>0 AND
  (state<>'closed' OR (NOT target_fenced AND exclusive_release_not_before>clock_timestamp()))) THEN
  RAISE EXCEPTION 'exclusive sessions must be safely released before downgrade';
 END IF;
END $$;
DROP TABLE exclusive_prepare_requests;
DROP TRIGGER exclusive_deadline ON sessions;
DROP FUNCTION record_exclusive_deadline();
DROP TABLE exclusive_targets;
ALTER TABLE sessions DROP CONSTRAINT sessions_id_tenant_unique;
ALTER TABLE sessions DROP CONSTRAINT exclusive_session_shape;
ALTER TABLE sessions DROP COLUMN exclusive_release_not_before, DROP COLUMN target_fenced,
 DROP COLUMN connect_deadline, DROP COLUMN prepared, DROP COLUMN target_epoch, DROP COLUMN target_accept_fence_hash;
ALTER TABLE applications DROP COLUMN exclusive_target;
