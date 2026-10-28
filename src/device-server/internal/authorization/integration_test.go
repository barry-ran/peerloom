//go:build integration

package authorization

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/identity"
	"github.com/barry-ran/peerloom/src/device-server/internal/migrate"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type testPresence struct {
	online bool
	err    error
}

func (p testPresence) Online(context.Context, string, string) (bool, error) { return p.online, p.err }

type fixture struct {
	service *Service
	pool    *pgxpool.Pool
	ctx     context.Context
	peers   []identity.Device
}

func setup(t *testing.T) fixture {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Fatal("integration target requires isolated TEST_DATABASE_URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	admin, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal("cannot connect to test PostgreSQL")
	}
	random := make([]byte, 8)
	if _, err = rand.Read(random); err != nil {
		t.Fatal(err)
	}
	schema := "peerloom_authorization_" + hex.EncodeToString(random)
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal("invalid test PostgreSQL URL")
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_, _ = admin.Exec(cleanup, "DROP SCHEMA "+quoted+" CASCADE")
		_ = admin.Close(cleanup)
	})
	dir, err := filepath.Abs("../../../../infra/migrations")
	if err != nil {
		t.Fatal(err)
	}
	ms, err := migrate.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = migrate.Apply(ctx, pool, ms, "up"); err != nil {
		t.Fatal(err)
	}
	service, err := New(pool, testPresence{online: true}, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	f := fixture{service: service, pool: pool, ctx: ctx}
	var tenant, otherTenant string
	if err = pool.QueryRow(ctx, "INSERT INTO tenants(name) VALUES('测试租户') RETURNING id::text").Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, "INSERT INTO tenants(name) VALUES('隔离租户') RETURNING id::text").Scan(&otherTenant); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		owner := tenant
		if i == 3 {
			owner = otherTenant
		}
		var app string
		if err = pool.QueryRow(ctx, "INSERT INTO applications(tenant_id,name) VALUES($1,'测试应用') RETURNING id::text", owner).Scan(&app); err != nil {
			t.Fatal(err)
		}
		var peer identity.Device
		if err = pool.QueryRow(ctx, `INSERT INTO devices(tenant_id,application_id,installation_key_hash,platform)
VALUES($1,$2,$3,'linux') RETURNING id::text,tenant_id::text,application_id::text`, owner, app, []byte{byte(i + 1)}).Scan(&peer.ID, &peer.TenantID, &peer.ApplicationID); err != nil {
			t.Fatal(err)
		}
		f.peers = append(f.peers, peer)
	}
	return f
}

func (f fixture) grant(t *testing.T, source, target int, action string, max int) string {
	t.Helper()
	var id string
	err := f.pool.QueryRow(f.ctx, `INSERT INTO connection_grants(tenant_id,source_device_id,target_device_id,expires_at,expiry_action,max_sessions)
VALUES($1,$2,$3,clock_timestamp()+interval '1 hour',$4,$5) RETURNING id::text`, f.peers[source].TenantID, f.peers[source].ID, f.peers[target].ID, action, max).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func requestID(i int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", i) }
func code(t *testing.T, err error, want string) {
	t.Helper()
	var public *Error
	if !errors.As(err, &public) || public.Code != want {
		t.Fatalf("expected %s, got %v", want, err)
	}
}
func (f fixture) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := f.pool.Exec(f.ctx, query, args...); err != nil {
		t.Fatal(err)
	}
}
func (f fixture) request(t *testing.T, i int) Session {
	t.Helper()
	value, err := f.service.Request(f.ctx, f.peers[0], f.peers[1].ID, requestID(i))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestDefaultDenyTenantDirectionAndPresence(t *testing.T) {
	f := setup(t)
	_, err := f.service.Request(f.ctx, f.peers[0], f.peers[1].ID, requestID(1))
	code(t, err, "GRANT_REQUIRED")
	f.grant(t, 0, 1, "terminate", 4)
	_, err = f.service.Request(f.ctx, f.peers[1], f.peers[0].ID, requestID(2))
	code(t, err, "GRANT_REQUIRED")
	_, err = f.service.Request(f.ctx, f.peers[0], f.peers[3].ID, requestID(3))
	code(t, err, "TARGET_NOT_FOUND")
	offline, _ := New(f.pool, testPresence{}, DefaultOptions())
	_, err = offline.Request(f.ctx, f.peers[0], f.peers[1].ID, requestID(4))
	code(t, err, "TARGET_OFFLINE")
	unavailable, _ := New(f.pool, testPresence{err: errors.New("redis unavailable")}, DefaultOptions())
	_, err = unavailable.Request(f.ctx, f.peers[0], f.peers[1].ID, requestID(5))
	code(t, err, "PRESENCE_UNAVAILABLE")
	value := f.request(t, 6)
	if value.State != "connecting" || value.GrantID == "" {
		t.Fatal("same-tenant cross-application grant failed")
	}
	_, err = f.service.AuthorizeSignal(f.ctx, f.peers[2], value.ID)
	code(t, err, "SESSION_NOT_FOUND")
	_, err = f.service.AuthorizeSignal(f.ctx, f.peers[3], value.ID)
	code(t, err, "SESSION_NOT_FOUND")
	_, err = f.service.Request(f.ctx, f.peers[0], f.peers[2].ID, requestID(6))
	code(t, err, "IDEMPOTENCY_CONFLICT")
}

func TestApprovalDescriptionsAndTargetRejection(t *testing.T) {
	f := setup(t)
	f.grant(t, 0, 1, "terminate", 2)
	f.exec(t, "UPDATE applications SET require_target_approval=true WHERE id=$1", f.peers[1].ApplicationID)
	value := f.request(t, 1)
	if value.State != "authorizing" {
		t.Fatal("target confirmation bypassed")
	}
	_, err := f.service.AuthorizeSignal(f.ctx, f.peers[0], value.ID)
	code(t, err, "TARGET_APPROVAL_REQUIRED")
	_, err = f.service.Respond(f.ctx, f.peers[0], value.ID, true)
	code(t, err, "TARGET_ONLY")
	value, err = f.service.Respond(f.ctx, f.peers[1], value.ID, true)
	if err != nil || value.State != "connecting" {
		t.Fatal("target acceptance failed", err)
	}
	_, err = f.service.MarkConnected(f.ctx, f.peers[0], value.ID)
	code(t, err, "NEGOTIATION_INCOMPLETE")
	_, err = f.service.AuthorizeDescription(f.ctx, f.peers[1], value.ID, "session.answer")
	code(t, err, "OFFER_REQUIRED")
	_, err = f.service.AuthorizeDescription(f.ctx, f.peers[1], value.ID, "session.offer")
	code(t, err, "SIGNAL_ROLE_FORBIDDEN")
	if _, err = f.service.AuthorizeDescription(f.ctx, f.peers[0], value.ID, "session.offer"); err != nil {
		t.Fatal(err)
	}
	_, err = f.service.AuthorizeDescription(f.ctx, f.peers[0], value.ID, "session.offer")
	code(t, err, "DESCRIPTION_ALREADY_SENT")
	if _, err = f.service.AuthorizeDescription(f.ctx, f.peers[1], value.ID, "session.answer"); err != nil {
		t.Fatal(err)
	}
	value, err = f.service.MarkConnected(f.ctx, f.peers[0], value.ID)
	if err != nil || value.State == "connected" {
		t.Fatal("single peer report claimed both connected")
	}
	value, err = f.service.MarkConnected(f.ctx, f.peers[1], value.ID)
	if err != nil || value.State != "connected" {
		t.Fatal("both reports not recorded")
	}
	value, err = f.service.Respond(f.ctx, f.peers[1], value.ID, false)
	if err != nil || value.State != "closed" || value.CloseReason != "TARGET_REJECTED" {
		t.Fatal("explicit rejection overridden")
	}
	_, err = f.service.AuthorizeSignal(f.ctx, f.peers[0], value.ID)
	code(t, err, "SESSION_CLOSED")
	if _, err = f.service.Respond(f.ctx, f.peers[1], value.ID, false); err != nil {
		t.Fatal("duplicate reject failed", err)
	}
}

func TestConcurrentGrantQuotaAndIdempotentRelease(t *testing.T) {
	f := setup(t)
	f.grant(t, 0, 1, "terminate", 1)
	f.exec(t, "UPDATE devices SET max_connections=50")
	var wg sync.WaitGroup
	results := make([]Session, 16)
	errs := make([]error, 16)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = f.service.Request(f.ctx, f.peers[0], f.peers[1].ID, requestID(i+1))
		}(i)
	}
	wg.Wait()
	successes := 0
	var winner Session
	for i, err := range errs {
		if err == nil {
			successes++
			winner = results[i]
		} else {
			code(t, err, "CONCURRENCY_LIMIT")
		}
	}
	if successes != 1 {
		t.Fatalf("grant quota admitted %d sessions", successes)
	}
	if _, err := f.service.Close(f.ctx, f.peers[0], winner.ID, "CLIENT_CLOSED"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Close(f.ctx, f.peers[0], winner.ID, "CLIENT_CLOSED"); err != nil {
		t.Fatal(err)
	}
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = f.service.Request(f.ctx, f.peers[0], f.peers[1].ID, requestID(99))
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
		if results[i].ID != results[0].ID {
			t.Fatal("request replay reserved another session")
		}
	}
	var count int
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM sessions WHERE state<>'closed'").Scan(&count); err != nil || count != 1 {
		t.Fatal("active quota inconsistent")
	}
}

func TestConcurrentDeviceQuotaAcrossDifferentGrants(t *testing.T) {
	f := setup(t)
	f.grant(t, 0, 1, "terminate", 5)
	f.grant(t, 0, 2, "terminate", 5)
	f.exec(t, "UPDATE devices SET max_connections=1 WHERE id=$1", f.peers[0].ID)
	results := make(chan error, 2)
	for i := 1; i <= 2; i++ {
		go func(i int) {
			_, err := f.service.Request(f.ctx, f.peers[0], f.peers[i].ID, requestID(i))
			results <- err
		}(i)
	}
	successes := 0
	for i := 0; i < 2; i++ {
		if err := <-results; err == nil {
			successes++
		} else {
			code(t, err, "CONCURRENCY_LIMIT")
		}
	}
	if successes != 1 {
		t.Fatalf("source device quota admitted %d", successes)
	}
}

func TestDualLeaseExpiryRevokeAndSnapshot(t *testing.T) {
	f := setup(t)
	grantID := f.grant(t, 0, 1, "no_new_connections", 2)
	value := f.request(t, 1)
	initial := value
	var err error
	value, err = f.service.Renew(f.ctx, f.peers[0], value.ID)
	if err != nil || !value.SourceLeaseExpiresAt.After(initial.SourceLeaseExpiresAt) || !value.TargetLeaseExpiresAt.Equal(initial.TargetLeaseExpiresAt) || !value.LeaseExpiresAt.Equal(initial.LeaseExpiresAt) {
		t.Fatal("one peer extended other peer's lease", err)
	}
	value, err = f.service.Renew(f.ctx, f.peers[1], value.ID)
	if err != nil || !value.LeaseExpiresAt.After(initial.LeaseExpiresAt) || value.LeaseGeneration != initial.LeaseGeneration+2 {
		t.Fatal("dual renewal failed", err)
	}
	f.exec(t, "UPDATE connection_grants SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", grantID)
	if _, err = f.service.Renew(f.ctx, f.peers[0], value.ID); err != nil {
		t.Fatal("existing no-new-connections session rejected", err)
	}
	_, err = f.service.Request(f.ctx, f.peers[0], f.peers[1].ID, requestID(2))
	code(t, err, "GRANT_REQUIRED")
	snapshot, err := f.service.Snapshot(f.ctx, f.peers[1])
	if err != nil || len(snapshot) != 1 || snapshot[0].ID != value.ID {
		t.Fatal("authorized snapshot failed", err)
	}
	closed, err := f.service.RevokeGrant(f.ctx, f.peers[0].TenantID, grantID)
	if err != nil || len(closed) != 1 || closed[0].State != "closed" {
		t.Fatal("revocation did not close existing session", err)
	}
	closed, err = f.service.RevokeGrant(f.ctx, f.peers[0].TenantID, grantID)
	if err != nil || len(closed) != 0 {
		t.Fatal("repeated revocation not idempotent", err)
	}
	_, err = f.service.Renew(f.ctx, f.peers[0], value.ID)
	code(t, err, "SESSION_CLOSED")
	f.grant(t, 0, 1, "terminate", 2)
	value = f.request(t, 3)
	f.exec(t, "UPDATE sessions SET target_lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", value.ID)
	_, err = f.service.Renew(f.ctx, f.peers[0], value.ID)
	code(t, err, "LEASE_EXPIRED")
	_, err = f.service.Renew(f.ctx, f.peers[1], value.ID)
	code(t, err, "SESSION_CLOSED")
	value = f.request(t, 4)
	f.exec(t, "UPDATE sessions SET source_lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", value.ID)
	closed, err = f.service.SweepExpired(f.ctx)
	if err != nil || len(closed) != 1 || closed[0].ID != value.ID {
		t.Fatal("expired lease sweep failed", err)
	}
}

func TestGrantExpiryAndDisabledPeerDenyRenewal(t *testing.T) {
	f := setup(t)
	grantID := f.grant(t, 0, 1, "terminate", 3)
	value := f.request(t, 1)
	f.exec(t, "UPDATE connection_grants SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", grantID)
	_, err := f.service.Renew(f.ctx, f.peers[0], value.ID)
	code(t, err, "GRANT_EXPIRED")
	f.grant(t, 0, 1, "no_new_connections", 3)
	f.exec(t, "UPDATE applications SET require_target_approval=true WHERE id=$1", f.peers[1].ApplicationID)
	value = f.request(t, 2)
	f.exec(t, "UPDATE connection_grants SET expires_at=clock_timestamp()-interval '1 second'")
	_, err = f.service.Respond(f.ctx, f.peers[1], value.ID, true)
	code(t, err, "GRANT_EXPIRED")
	f.grant(t, 0, 1, "terminate", 3)
	f.exec(t, "UPDATE applications SET require_target_approval=false WHERE id=$1", f.peers[1].ApplicationID)
	value = f.request(t, 3)
	f.exec(t, "UPDATE applications SET enabled=false WHERE id=$1", f.peers[1].ApplicationID)
	_, err = f.service.Renew(f.ctx, f.peers[0], value.ID)
	code(t, err, "TARGET_NOT_CONNECTABLE")
}

func TestConcurrentDescriptionsAndRevocation(t *testing.T) {
	f := setup(t)
	grantID := f.grant(t, 0, 1, "no_new_connections", 50)
	f.exec(t, "UPDATE devices SET max_connections=50")
	value := f.request(t, 1)
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = f.service.AuthorizeDescription(f.ctx, f.peers[0], value.ID, "session.offer")
		}(i)
	}
	wg.Wait()
	successes := 0
	for _, err := range errs {
		if err == nil {
			successes++
		} else {
			code(t, err, "DESCRIPTION_ALREADY_SENT")
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent offer admitted %d descriptions", successes)
	}
	// An unrelated management tenant must not revoke this grant.
	_, err := f.service.RevokeGrant(f.ctx, f.peers[3].TenantID, grantID)
	code(t, err, "GRANT_REQUIRED")
	barrier := make(chan struct{})
	requestErrors := make([]error, 8)
	renewErrors := make([]error, 8)
	var revokeError error
	for i := range requestErrors {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			<-barrier
			_, requestErrors[i] = f.service.Request(f.ctx, f.peers[0], f.peers[1].ID, requestID(i+100))
		}(i)
		go func(i int) {
			defer wg.Done()
			<-barrier
			_, renewErrors[i] = f.service.Renew(f.ctx, f.peers[0], value.ID)
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-barrier
		_, revokeError = f.service.RevokeGrant(f.ctx, f.peers[0].TenantID, grantID)
	}()
	close(barrier)
	wg.Wait()
	if revokeError != nil {
		t.Fatal(revokeError)
	}
	for _, err := range requestErrors {
		if err != nil {
			code(t, err, "GRANT_REQUIRED")
		}
	}
	for _, err := range renewErrors {
		if err != nil {
			code(t, err, "SESSION_CLOSED")
		}
	}
	var active int
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM sessions WHERE state<>'closed'").Scan(&active); err != nil || active != 0 {
		t.Fatal("revocation race resurrected an active session")
	}
}

func TestConnectableOnlyControlsNewSessions(t *testing.T) {
	f := setup(t)
	f.grant(t, 0, 1, "terminate", 3)
	value := f.request(t, 1)
	f.exec(t, "UPDATE devices SET connectable=false WHERE id=$1", f.peers[1].ID)
	if _, err := f.service.Renew(f.ctx, f.peers[0], value.ID); err != nil {
		t.Fatal("connectable=false terminated an already accepted session", err)
	}
	if _, err := f.service.AuthorizeSignal(f.ctx, f.peers[1], value.ID); err != nil {
		t.Fatal("existing authorized signaling was blocked", err)
	}
	_, err := f.service.Request(f.ctx, f.peers[0], f.peers[1].ID, requestID(2))
	code(t, err, "TARGET_NOT_CONNECTABLE")
	f.exec(t, "UPDATE devices SET status='revoked' WHERE id=$1", f.peers[1].ID)
	_, err = f.service.Renew(f.ctx, f.peers[0], value.ID)
	code(t, err, "TARGET_NOT_CONNECTABLE")
}

func TestExpiredQuotaRemainsVisibleToSweep(t *testing.T) {
	f := setup(t)
	f.grant(t, 0, 1, "terminate", 1)
	f.exec(t, "UPDATE devices SET max_connections=1")
	expired := f.request(t, 1)
	f.exec(t, "UPDATE sessions SET target_lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", expired.ID)
	replacement := f.request(t, 2)
	var state string
	if err := f.pool.QueryRow(f.ctx, "SELECT state FROM sessions WHERE id=$1", expired.ID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state == "closed" {
		t.Fatal("admission silently consumed sweep's termination notification")
	}
	closed, err := f.service.SweepExpired(f.ctx)
	if err != nil || len(closed) != 1 || closed[0].ID != expired.ID {
		t.Fatal("expired reservation did not remain sweep-visible", err)
	}
	if _, err = f.service.AuthorizeSignal(f.ctx, f.peers[0], replacement.ID); err != nil {
		t.Fatal("replacement session lost authorization", err)
	}
	_, err = f.service.Request(f.ctx, f.peers[0], f.peers[1].ID, requestID(3))
	code(t, err, "CONCURRENCY_LIMIT")
}
