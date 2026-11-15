-- Never rebind shared replay authority to one key on downgrade.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM tenant_service_credentials WHERE subject_id<>id)
 OR EXISTS(SELECT 1 FROM service_subjects WHERE revoked_at IS NOT NULL) THEN
  RAISE EXCEPTION 'cannot downgrade renewed or revoked service subjects';
 END IF;
END $$;
DROP TABLE service_key_renewals;
ALTER TABLE service_subjects DROP CONSTRAINT subject_current_key_fk;
ALTER TABLE tenant_service_credentials DROP CONSTRAINT credential_subject_unique, DROP CONSTRAINT credential_subject_tenant_scope_unique;
ALTER TABLE management_requests DROP CONSTRAINT management_requests_subject_fk;
ALTER TABLE management_requests RENAME COLUMN service_subject_id TO service_credential_id;
ALTER TABLE management_requests ADD CONSTRAINT management_requests_service_credential_id_tenant_id_fkey
 FOREIGN KEY(service_credential_id,tenant_id) REFERENCES tenant_service_credentials(id,tenant_id);
ALTER TABLE tenant_service_credentials DROP CONSTRAINT credential_subject_scope_fk;
ALTER TABLE tenant_service_credentials DROP COLUMN subject_id, DROP COLUMN accept_until;
DROP TABLE service_subjects;
