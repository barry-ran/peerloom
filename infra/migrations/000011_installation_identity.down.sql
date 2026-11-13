-- 无法从长期凭据推导旧版到期时间，禁止带身份降级。
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM device_credentials) THEN
  RAISE EXCEPTION 'cannot downgrade populated long-lived identity store';
 END IF;
END $$;
ALTER TABLE device_credentials ADD COLUMN expires_at timestamptz NOT NULL, ADD COLUMN rotated_at timestamptz;
ALTER TABLE devices RENAME COLUMN installation_tag_hash TO installation_key_hash;
