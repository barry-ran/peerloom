DROP TABLE relay_session_snapshot_nodes;
DROP TABLE relay_session_snapshots;
DROP TABLE relay_secret_versions;
ALTER TABLE relay_nodes DROP COLUMN secret_version;
