CREATE TABLE service_subjects (
 id uuid PRIMARY KEY,
 tenant_id uuid NOT NULL REFERENCES tenants(id),
 scope text NOT NULL CHECK(scope IN ('read','admin')),
 revoked_at timestamptz,
 current_credential_id uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(id,tenant_id,scope)
);
INSERT INTO service_subjects(id,tenant_id,scope,revoked_at,current_credential_id,created_at)
 SELECT id,tenant_id,scope,revoked_at,id,created_at FROM tenant_service_credentials;
ALTER TABLE tenant_service_credentials ADD COLUMN subject_id uuid, ADD COLUMN accept_until timestamptz;
UPDATE tenant_service_credentials SET subject_id=id;
ALTER TABLE tenant_service_credentials ALTER COLUMN subject_id SET NOT NULL;
ALTER TABLE tenant_service_credentials ADD CONSTRAINT credential_subject_scope_fk
 FOREIGN KEY(subject_id,tenant_id,scope) REFERENCES service_subjects(id,tenant_id,scope);
ALTER TABLE management_requests DROP CONSTRAINT management_requests_service_credential_id_tenant_id_fkey;
ALTER TABLE management_requests RENAME COLUMN service_credential_id TO service_subject_id;
ALTER TABLE service_subjects ADD CONSTRAINT service_subject_tenant_unique UNIQUE(id,tenant_id);
ALTER TABLE management_requests ADD CONSTRAINT management_requests_subject_fk
 FOREIGN KEY(service_subject_id,tenant_id) REFERENCES service_subjects(id,tenant_id);

ALTER TABLE tenant_service_credentials ADD CONSTRAINT credential_subject_unique UNIQUE(id,subject_id);
ALTER TABLE tenant_service_credentials ADD CONSTRAINT credential_subject_tenant_scope_unique UNIQUE(id,subject_id,tenant_id,scope);
ALTER TABLE service_subjects ADD CONSTRAINT subject_current_key_fk
 FOREIGN KEY(current_credential_id,id,tenant_id,scope)
 REFERENCES tenant_service_credentials(id,subject_id,tenant_id,scope) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE service_key_renewals (
 previous_credential_id uuid PRIMARY KEY REFERENCES tenant_service_credentials(id),
 next_credential_id uuid NOT NULL UNIQUE REFERENCES tenant_service_credentials(id),
 subject_id uuid NOT NULL REFERENCES service_subjects(id),
 operation_hash bytea NOT NULL CHECK(octet_length(operation_hash)=32),
 response_nonce bytea CHECK(response_nonce IS NULL OR octet_length(response_nonce)=12),
 response_ciphertext bytea,
 replay_until timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(previous_credential_id,subject_id) REFERENCES tenant_service_credentials(id,subject_id),
FOREIGN KEY(next_credential_id,subject_id) REFERENCES tenant_service_credentials(id,subject_id),
CHECK((response_nonce IS NULL)=(response_ciphertext IS NULL))
);
CREATE INDEX service_key_renewals_expiry_idx ON service_key_renewals(replay_until);
