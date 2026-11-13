-- 开发期破坏性身份格式变更。禁止静默延长旧限期凭据；有旧身份时明确失败。
-- 操作者须另行决定迁移或重建开发数据库，不能由升级自动删除身份。
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM device_credentials) THEN
  RAISE EXCEPTION 'legacy device credentials require explicit development identity migration or rebuild';
 END IF;
END $$;
ALTER TABLE device_credentials DROP COLUMN expires_at, DROP COLUMN rotated_at;
ALTER TABLE devices RENAME COLUMN installation_key_hash TO installation_tag_hash;
