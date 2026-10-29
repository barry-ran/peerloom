-- Exclusive ownership is authoritative PostgreSQL state, never Redis presence.
ALTER TABLE applications ADD COLUMN exclusive_target boolean NOT NULL DEFAULT false;
ALTER TABLE sessions ADD COLUMN target_epoch bigint NOT NULL DEFAULT 0 CHECK (target_epoch >= 0);
ALTER TABLE sessions ADD COLUMN target_accept_fence_hash bytea CHECK (target_accept_fence_hash IS NULL OR octet_length(target_accept_fence_hash)=32);
ALTER TABLE sessions ADD COLUMN prepared boolean NOT NULL DEFAULT false;
ALTER TABLE sessions ADD COLUMN connect_deadline timestamptz;
ALTER TABLE sessions ADD COLUMN target_fenced boolean NOT NULL DEFAULT false;
ALTER TABLE sessions ADD COLUMN exclusive_release_not_before timestamptz;
ALTER TABLE sessions ADD CONSTRAINT exclusive_session_shape CHECK (
 (target_epoch = 0 AND NOT prepared AND connect_deadline IS NULL AND NOT target_fenced AND exclusive_release_not_before IS NULL)
 OR (target_epoch > 0 AND connect_deadline IS NOT NULL AND exclusive_release_not_before IS NOT NULL));
ALTER TABLE sessions ADD CONSTRAINT sessions_id_tenant_unique UNIQUE(id,tenant_id);
CREATE TABLE exclusive_targets (
 tenant_id uuid NOT NULL REFERENCES tenants(id),
 target_device_id uuid NOT NULL,
 epoch bigint NOT NULL DEFAULT 0 CHECK (epoch >= 0),
 session_id uuid,
 owner_device_id uuid,
 release_not_before timestamptz NOT NULL DEFAULT 'epoch',
 target_fenced boolean NOT NULL DEFAULT false,
 PRIMARY KEY (tenant_id,target_device_id),
 FOREIGN KEY (target_device_id,tenant_id) REFERENCES devices(id,tenant_id),
 FOREIGN KEY (owner_device_id,tenant_id) REFERENCES devices(id,tenant_id),
 FOREIGN KEY (session_id,tenant_id) REFERENCES sessions(id,tenant_id)
);
-- Every lease-changing path records its high-water mark BEFORE the row can be
-- returned and sent. Closing/revocation never erases already-issued authority.
CREATE FUNCTION record_exclusive_deadline() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.target_epoch > 0 THEN
  NEW.exclusive_release_not_before := GREATEST(
   NEW.exclusive_release_not_before,
   NEW.source_lease_expires_at + interval '2 seconds',
   NEW.target_lease_expires_at + interval '2 seconds');
  IF TG_OP = 'UPDATE' THEN
   NEW.exclusive_release_not_before := GREATEST(NEW.exclusive_release_not_before, OLD.exclusive_release_not_before);
  END IF;
  UPDATE exclusive_targets SET release_not_before=GREATEST(release_not_before,NEW.exclusive_release_not_before)
   WHERE tenant_id=NEW.tenant_id AND target_device_id=NEW.target_device_id AND epoch=NEW.target_epoch;
  IF NOT FOUND THEN
   -- Historical terminal ACK/revocation may touch the old row after takeover.
   -- It cannot expand authority or affect the new resource's high-water mark.
   IF TG_OP <> 'UPDATE' THEN RAISE EXCEPTION 'exclusive ownership unavailable'; END IF;
   IF OLD.state <> 'closed' OR NEW.state <> 'closed'
    OR NEW.target_epoch <> OLD.target_epoch
    OR NEW.source_lease_expires_at > OLD.source_lease_expires_at
    OR NEW.target_lease_expires_at > OLD.target_lease_expires_at
    OR NEW.exclusive_release_not_before > OLD.exclusive_release_not_before THEN
     RAISE EXCEPTION 'exclusive ownership unavailable';
   END IF;
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER exclusive_deadline BEFORE INSERT OR UPDATE ON sessions
 FOR EACH ROW EXECUTE FUNCTION record_exclusive_deadline();

-- Non-secret idempotency records retain the exact resource, never a stale grant
-- response. No automatic deletion: an old key cannot silently acquire a new owner.
CREATE TABLE exclusive_prepare_requests (
 tenant_id uuid NOT NULL REFERENCES tenants(id),
 credential_id uuid NOT NULL,
 key_hash bytea NOT NULL CHECK(octet_length(key_hash)=32),
 request_hash bytea NOT NULL CHECK(octet_length(request_hash)=32),
 session_id uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,credential_id,key_hash),
 FOREIGN KEY(session_id,tenant_id) REFERENCES sessions(id,tenant_id)
);
