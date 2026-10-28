ALTER TABLE webhook_endpoints ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK(revision>0);
CREATE UNIQUE INDEX webhook_endpoints_tenant_identity_idx ON webhook_endpoints(id,tenant_id);
CREATE INDEX webhook_endpoints_tenant_page_idx ON webhook_endpoints(tenant_id,created_at,id);
CREATE TABLE webhook_deliveries (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL REFERENCES tenants(id),
 endpoint_id uuid NOT NULL,
 endpoint_revision bigint NOT NULL,
 audit_id bigint NOT NULL REFERENCES audit_events(id),
 payload jsonb NOT NULL CHECK(octet_length(payload::text)<=8192),
 state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','delivered','failed','cancelled')),
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 8),
 next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 last_status integer CHECK(last_status BETWEEN 100 AND 599),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 finished_at timestamptz,
 FOREIGN KEY(endpoint_id,tenant_id) REFERENCES webhook_endpoints(id,tenant_id),
 UNIQUE(endpoint_id,audit_id)
);
CREATE INDEX webhook_deliveries_due_idx ON webhook_deliveries(next_attempt_at,id) WHERE state='pending';
CREATE INDEX webhook_deliveries_endpoint_pending_idx ON webhook_deliveries(endpoint_id) WHERE state='pending';
CREATE INDEX webhook_deliveries_retention_idx ON webhook_deliveries(finished_at) WHERE state<>'pending';
-- Exactly the audited control-plane events below are supported. No credential,
-- arbitrary audit details, admin login, or unimplemented presence event is sent.
CREATE FUNCTION peerloom_enqueue_webhook_audit() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE endpoint record;
BEGIN
 IF NEW.tenant_id IS NULL OR NEW.action NOT IN ('application.create','application.update','device.update','device.revoke','device.register.direct','connection_grant.create','connection_grant.revoke','session.terminate') THEN RETURN NEW; END IF;
 FOR endpoint IN SELECT id,revision FROM webhook_endpoints WHERE tenant_id=NEW.tenant_id AND enabled ORDER BY id FOR UPDATE LOOP
  IF (SELECT count(*) FROM webhook_deliveries WHERE endpoint_id=endpoint.id AND state='pending') >= 1000 THEN
   RAISE EXCEPTION 'webhook pending queue capacity exceeded' USING ERRCODE='P0001';
  END IF;
  INSERT INTO webhook_deliveries(tenant_id,endpoint_id,endpoint_revision,audit_id,payload)
  VALUES(NEW.tenant_id,endpoint.id,endpoint.revision,NEW.id,jsonb_build_object('version',1,'event_id',NEW.id::text,'tenant_id',NEW.tenant_id,'event',NEW.action,'resource_type',NEW.resource_type,'resource_id',NEW.resource_id,'occurred_at',to_char(NEW.created_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')));
 END LOOP;
 RETURN NEW;
END $$;
CREATE TRIGGER peerloom_webhook_audit_outbox AFTER INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION peerloom_enqueue_webhook_audit();
