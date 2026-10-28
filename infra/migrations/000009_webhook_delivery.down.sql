DROP TRIGGER peerloom_webhook_audit_outbox ON audit_events;
DROP FUNCTION peerloom_enqueue_webhook_audit();
DROP TABLE webhook_deliveries;
DROP INDEX webhook_endpoints_tenant_page_idx,webhook_endpoints_tenant_identity_idx;
ALTER TABLE webhook_endpoints DROP COLUMN revision;
