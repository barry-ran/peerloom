ALTER TABLE direct_registration_windows DROP CONSTRAINT direct_registration_windows_attempts_check;
ALTER TABLE direct_registration_windows ADD CONSTRAINT direct_registration_windows_attempts_check CHECK (attempts BETWEEN 1 AND 6001);
-- Fail closed if unlimited policies exist: operators must explicitly replace them
-- before rollback. Never silently convert unlimited to an arbitrary historical cap.
ALTER TABLE applications DROP CONSTRAINT applications_max_connections_check;
ALTER TABLE applications ADD CONSTRAINT applications_max_connections_check CHECK (max_connections >= 0);
ALTER TABLE applications ALTER COLUMN max_connections SET DEFAULT 8;
ALTER TABLE devices DROP CONSTRAINT devices_max_connections_check;
ALTER TABLE devices ADD CONSTRAINT devices_max_connections_check CHECK (max_connections >= 0);
ALTER TABLE connection_grants DROP CONSTRAINT connection_grants_max_sessions_check;
ALTER TABLE connection_grants ADD CONSTRAINT connection_grants_max_sessions_check CHECK (max_sessions > 0);
ALTER TABLE connection_grants ALTER COLUMN max_sessions SET DEFAULT 1;
ALTER TABLE sessions DROP CONSTRAINT sessions_negotiation_generation_check;
ALTER TABLE sessions ADD CONSTRAINT sessions_negotiation_generation_check CHECK (negotiation_generation BETWEEN 1 AND 32);
ALTER TABLE sessions ALTER COLUMN negotiation_generation TYPE integer;
ALTER TABLE relay_issuances DROP CONSTRAINT relay_issuances_negotiation_generation_check;
ALTER TABLE relay_issuances ADD CONSTRAINT relay_issuances_negotiation_generation_check CHECK (negotiation_generation BETWEEN 1 AND 32);
ALTER TABLE relay_issuances ALTER COLUMN negotiation_generation TYPE integer;
