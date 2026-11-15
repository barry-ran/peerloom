DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM relay_secret_versions) OR EXISTS(SELECT 1 FROM relay_session_snapshots) THEN
  RAISE EXCEPTION 'managed relay secrets or snapshots prevent destructive downgrade';
 END IF;
END $$;
DROP TABLE relay_session_snapshot_nodes;
DROP TABLE relay_session_snapshots;
DROP TABLE relay_secret_versions;
ALTER TABLE relay_nodes DROP COLUMN secret_version;
