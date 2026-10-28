ALTER TABLE sessions ADD COLUMN negotiation_generation integer NOT NULL DEFAULT 1
    CHECK(negotiation_generation BETWEEN 1 AND 32);
ALTER TABLE sessions ADD COLUMN negotiation_started_at timestamptz NOT NULL DEFAULT clock_timestamp();
ALTER TABLE relay_issuances DROP CONSTRAINT relay_issuances_negotiation_generation_check;
ALTER TABLE relay_issuances ADD CONSTRAINT relay_issuances_negotiation_generation_check
    CHECK(negotiation_generation BETWEEN 1 AND 32);
