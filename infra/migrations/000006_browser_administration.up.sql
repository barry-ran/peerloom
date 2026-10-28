-- Browser administrators are not tenant service credentials or device identities.
CREATE TABLE admin_users (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL REFERENCES tenants(id),
 username text NOT NULL CHECK(username ~ '^[a-z0-9][a-z0-9_.-]{2,63}$'),
 password_hash text NOT NULL CHECK(length(password_hash) BETWEEN 80 AND 256),
 scope text NOT NULL CHECK(scope IN ('read','admin')),
 enabled boolean NOT NULL DEFAULT true,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(tenant_id,username), UNIQUE(id,tenant_id)
);
CREATE TABLE admin_sessions (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL REFERENCES tenants(id),
 user_id uuid NOT NULL,
 token_hash bytea NOT NULL UNIQUE CHECK(octet_length(token_hash)=32),
 csrf_token text NOT NULL CHECK(length(csrf_token)=43),
 expires_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(user_id,tenant_id) REFERENCES admin_users(id,tenant_id) ON DELETE CASCADE,
 CHECK(expires_at>created_at)
);
CREATE INDEX admin_sessions_user_idx ON admin_sessions(user_id,created_at DESC,id);
CREATE INDEX admin_sessions_expiry_idx ON admin_sessions(expires_at);
CREATE TABLE admin_login_windows (
 key_hash bytea NOT NULL CHECK(octet_length(key_hash)=32),
 window_start timestamptz NOT NULL,
 attempts integer NOT NULL CHECK(attempts BETWEEN 1 AND 121),
 PRIMARY KEY(key_hash,window_start)
);
CREATE TABLE admin_management_requests (LIKE management_requests INCLUDING DEFAULTS INCLUDING CONSTRAINTS);
ALTER TABLE admin_management_requests RENAME COLUMN service_credential_id TO admin_user_id;
ALTER TABLE admin_management_requests ADD PRIMARY KEY(tenant_id,admin_user_id,operation,key_hash);
ALTER TABLE admin_management_requests ADD FOREIGN KEY(tenant_id) REFERENCES tenants(id);
ALTER TABLE admin_management_requests ADD FOREIGN KEY(admin_user_id,tenant_id) REFERENCES admin_users(id,tenant_id);
CREATE INDEX admin_management_requests_expiry_idx ON admin_management_requests(expires_at);
CREATE INDEX admin_management_requests_response_expiry_idx ON admin_management_requests(response_expires_at) WHERE response_ciphertext IS NOT NULL;
