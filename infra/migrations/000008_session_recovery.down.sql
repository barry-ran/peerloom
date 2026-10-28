-- Older binaries cannot safely interpret an already restarted session.
UPDATE sessions SET state='closed',close_reason='PROTOCOL_DOWNGRADE',closed_at=clock_timestamp()
WHERE negotiation_generation>1 AND state<>'closed';
DELETE FROM relay_issuances WHERE negotiation_generation>1;
ALTER TABLE relay_issuances DROP CONSTRAINT relay_issuances_negotiation_generation_check;
ALTER TABLE relay_issuances ADD CONSTRAINT relay_issuances_negotiation_generation_check CHECK(negotiation_generation=1);
ALTER TABLE sessions DROP COLUMN negotiation_started_at;
ALTER TABLE sessions DROP COLUMN negotiation_generation;
