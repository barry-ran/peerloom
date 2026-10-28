-- Quota authority is PostgreSQL, shared by every server instance. IPs are hashed.
CREATE TABLE direct_registration_windows (
 key_hash bytea NOT NULL CHECK(octet_length(key_hash)=32),
 window_start timestamptz NOT NULL,
 attempts integer NOT NULL CHECK(attempts BETWEEN 1 AND 6001),
 PRIMARY KEY(key_hash,window_start)
);
CREATE INDEX direct_registration_windows_expiry_idx ON direct_registration_windows(window_start);
-- Permanent bounded receipt tombstones prevent an expired recovery key from
-- silently creating a second device. Secret response ciphertext remains short-lived.
CREATE TABLE direct_registration_receipts (
 tenant_id uuid NOT NULL REFERENCES tenants(id),
 application_id uuid NOT NULL,
 key_hash bytea NOT NULL CHECK(octet_length(key_hash)=32),
 request_hash bytea NOT NULL CHECK(octet_length(request_hash)=32),
 device_id uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(application_id,key_hash),
 FOREIGN KEY(application_id,tenant_id) REFERENCES applications(id,tenant_id),
 FOREIGN KEY(device_id,tenant_id) REFERENCES devices(id,tenant_id)
);
CREATE INDEX direct_registration_receipts_quota_idx ON direct_registration_receipts(application_id,created_at);
