//go:build integration

package management

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/webhook"
)

func setupWebhook(t *testing.T, f fixture) WebhookEndpoint {
	t.Helper()
	registry, err := webhook.NewRegistry([]webhook.Binding{{TenantID: f.principal.TenantID(), URL: "https://hooks.example.com/peerloom", SecretRef: "test", Secret: strings.Repeat("s", 32), Addresses: []string{"8.8.8.8"}}})
	if err != nil {
		t.Fatal(err)
	}
	f.service.webhookRegistry = registry
	endpoint, err := f.service.CreateWebhook(f.ctx, f.principal, WebhookInput{URL: "https://hooks.example.com/peerloom", SecretRef: "test"}, "create-webhook")
	if err != nil {
		t.Fatal(err)
	}
	return endpoint
}
func TestWebhookUUIDReplayAndIsolation(t *testing.T) {
	f := setup(t)
	endpoint := setupWebhook(t, f)
	change := WebhookUpdate{Enabled: ptr(false)}
	first, err := f.service.UpdateWebhook(f.ctx, f.principal, strings.ToUpper(endpoint.ID), change, "disable-webhook")
	if err != nil {
		t.Fatal(err)
	}
	replay, err := f.service.UpdateWebhook(f.ctx, f.principal, strings.ToLower(endpoint.ID), change, "disable-webhook")
	if err != nil || first.Revision != 2 || replay.Revision != 2 {
		t.Fatalf("case canonical replay: %d %d %v", first.Revision, replay.Revision, err)
	}
	other, err := BootstrapKey(f.ctx, f.pool, "other", ScopeAdmin, time.Hour, "other")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := f.service.Authenticate(f.ctx, other.ServiceCredential)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.service.UpdateWebhook(f.ctx, principal, endpoint.ID, change, "cross-tenant")
	requireCode(t, err, "WEBHOOK_NOT_FOUND")
	var count int
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM audit_events WHERE action=$1", "webhook.update:"+endpoint.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("single update audit: %d %v", count, err)
	}
}

type webhookRecorder struct {
	ids    []string
	status int
}

func (s *webhookRecorder) Send(_ context.Context, _, _, _, id string, body []byte) (int, error) {
	s.ids = append(s.ids, id)
	return s.status, nil
}
func TestWebhookOutboxRetryIdentityAndDisable(t *testing.T) {
	f := setup(t)
	endpoint := setupWebhook(t, f)
	if _, err := f.service.CreateApplication(f.ctx, f.principal, ApplicationInput{Name: "event"}, "event-create"); err != nil {
		t.Fatal(err)
	}
	sender := &webhookRecorder{status: 503}
	worker, err := webhook.NewWorker(f.pool, sender)
	if err != nil {
		t.Fatal(err)
	}
	if worked, err := worker.DeliverOne(f.ctx); err != nil || !worked {
		t.Fatalf("first attempt: %v %v", worked, err)
	}
	if _, err = f.pool.Exec(f.ctx, "UPDATE webhook_deliveries SET next_attempt_at=clock_timestamp()"); err != nil {
		t.Fatal(err)
	}
	sender.status = 204
	if worked, err := worker.DeliverOne(f.ctx); err != nil || !worked {
		t.Fatalf("retry: %v %v", worked, err)
	}
	if len(sender.ids) != 2 || sender.ids[0] != sender.ids[1] {
		t.Fatal("retry changed delivery identity")
	}
	if _, err = f.service.CreateApplication(f.ctx, f.principal, ApplicationInput{Name: "cancelled-event"}, "event-create-2"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.UpdateWebhook(f.ctx, f.principal, endpoint.ID, WebhookUpdate{Enabled: ptr(false)}, "disable-webhook"); err != nil {
		t.Fatal(err)
	}
	if worked, err := worker.DeliverOne(f.ctx); err != nil || !worked {
		t.Fatalf("cancel: %v %v", worked, err)
	}
	if len(sender.ids) != 2 {
		t.Fatal("disabled endpoint delivered")
	}
	var delivered, cancelled int
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*) FILTER (WHERE state='delivered'),count(*) FILTER (WHERE state='cancelled') FROM webhook_deliveries").Scan(&delivered, &cancelled); err != nil || delivered != 1 || cancelled != 1 {
		t.Fatalf("delivery states %d %d %v", delivered, cancelled, err)
	}
}

func TestWebhookBackpressureRollsBackMutation(t *testing.T) {
	f := setup(t)
	endpoint := setupWebhook(t, f)
	_, err := f.pool.Exec(f.ctx, `WITH audit AS (
 INSERT INTO audit_events(tenant_id,actor_type,action,resource_type,resource_id) SELECT $1,'test','fixture','application',gen_random_uuid()::text FROM generate_series(1,1000) RETURNING id,tenant_id
 ) INSERT INTO webhook_deliveries(tenant_id,endpoint_id,endpoint_revision,audit_id,payload) SELECT tenant_id,$2,1,id,'{}'::jsonb FROM audit`, f.principal.TenantID(), endpoint.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.CreateApplication(f.ctx, f.principal, ApplicationInput{Name: "must-roll-back"}, "queue-full-create"); err == nil {
		t.Fatal("full outbox accepted audited mutation")
	}
	var count int
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM applications WHERE name='must-roll-back'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial mutation %d %v", count, err)
	}
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM webhook_deliveries").Scan(&count); err != nil || count != 1000 {
		t.Fatalf("queue bound %d %v", count, err)
	}
}
