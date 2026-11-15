ALTER TABLE relay_nodes ADD COLUMN secret_version bigint NOT NULL DEFAULT 0 CHECK(secret_version>=0);
CREATE TABLE relay_secret_versions (
 node_id uuid NOT NULL REFERENCES relay_nodes(id),
 version bigint NOT NULL CHECK(version>0),
 tenant_id uuid REFERENCES tenants(id),
 key_id text NOT NULL CHECK(length(key_id)=64),
 nonce bytea NOT NULL CHECK(octet_length(nonce)=12),
 ciphertext bytea NOT NULL CHECK(octet_length(ciphertext) BETWEEN 48 AND 272),
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(node_id,version)
);
CREATE TABLE relay_session_snapshots (
 tenant_id uuid NOT NULL REFERENCES tenants(id),
 session_id uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,session_id),
 FOREIGN KEY(session_id,tenant_id) REFERENCES sessions(id,tenant_id)
);
CREATE TABLE relay_session_snapshot_nodes (
 tenant_id uuid NOT NULL,
 session_id uuid NOT NULL,
 ordinal smallint NOT NULL CHECK(ordinal BETWEEN 0 AND 3),
 node_id uuid NOT NULL,
 node_revision bigint NOT NULL CHECK(node_revision>0),
 endpoint text NOT NULL,
 secret_version bigint NOT NULL,
 PRIMARY KEY(tenant_id,session_id,ordinal),
 UNIQUE(tenant_id,session_id,node_id),
 FOREIGN KEY(tenant_id,session_id) REFERENCES relay_session_snapshots(tenant_id,session_id),
 FOREIGN KEY(node_id,secret_version) REFERENCES relay_secret_versions(node_id,version)
);
-- Immutable versions and session snapshots must survive configuration changes.
-- No purge or cascade deletes old secrets. Session authorization still gates use.
