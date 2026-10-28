//go:build integration

package management

import (
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/relay"
)

func setupRelay(t *testing.T, f fixture) *relay.Issuer {
	t.Helper()
	issuer, err := relay.New(map[string]relay.SecretBinding{"tenant-v1": {TenantID: f.principal.TenantID(), Secret: []byte(strings.Repeat("s", 32)), URLs: []string{"turn:relay.example.com:3478?transport=udp"}}, "shared-v1": {Secret: []byte(strings.Repeat("x", 32)), URLs: []string{"turn:shared.example.com:3478?transport=udp"}}}, 5*time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	f.service.relayIssuer = issuer
	return issuer
}
func relayInput() RelayNodeInput {
	return RelayNodeInput{Name: "测试中继", Region: "test", Endpoint: "turn:relay.example.com:3478?transport=udp", SecretRef: "tenant-v1"}
}
func TestRelayManagementApprovalIsolationAndRevision(t *testing.T) {
	f := setup(t)
	setupRelay(t, f)
	input := relayInput()
	node, err := f.service.CreateRelayNode(f.ctx, f.principal, input, "relay-create")
	if err != nil {
		t.Fatal(err)
	}
	replay, err := f.service.CreateRelayNode(f.ctx, f.principal, input, "relay-create")
	if err != nil || node.ID != replay.ID {
		t.Fatalf("node replay: %v", err)
	}
	bad := input
	bad.Endpoint = "turn:attacker.example.com:3478?transport=udp"
	_, err = f.service.CreateRelayNode(f.ctx, f.principal, bad, "bad-url")
	requireCode(t, err, "RELAY_BINDING_NOT_APPROVED")
	bad.Endpoint = "turn:shared.example.com:3478?transport=udp"
	bad.SecretRef = "shared-v1"
	_, err = f.service.CreateRelayNode(f.ctx, f.principal, bad, "shared-reference")
	requireCode(t, err, "RELAY_BINDING_NOT_APPROVED")
	otherKey, err := BootstrapKey(f.ctx, f.pool, "other", ScopeAdmin, time.Hour, "other")
	if err != nil {
		t.Fatal(err)
	}
	other, err := f.service.Authenticate(f.ctx, otherKey.ServiceCredential)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.service.GetRelayNode(f.ctx, other, node.ID)
	requireCode(t, err, "RELAY_NODE_NOT_FOUND")
	_, err = f.service.UpdateRelayNode(f.ctx, other, node.ID, RelayNodeUpdate{Enabled: ptr(false)}, "cross-tenant-disable")
	requireCode(t, err, "RELAY_NODE_NOT_FOUND")
	updated, err := f.service.UpdateRelayNode(f.ctx, f.principal, node.ID, RelayNodeUpdate{Enabled: ptr(false)}, "disable-node")
	if err != nil || updated.Enabled || updated.Revision != 2 {
		t.Fatalf("disable: %v", err)
	}
	page, err := f.service.ListRelayNodes(f.ctx, f.principal, Page{Limit: 1})
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != node.ID {
		t.Fatalf("node page: %v", err)
	}
}
func TestRelayDurableReuseLimitsAndRevocation(t *testing.T) {
	f := setup(t)
	issuer := setupRelay(t, f)
	pair := makePair(t, f)
	session, err := pair.auth.Request(f.ctx, pair.actors[0], pair.actors[1].ID, "00000000-0000-0000-0000-000000000091")
	if err != nil {
		t.Fatal(err)
	}
	service, err := relay.NewService(f.pool, issuer, pair.auth, relay.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	empty, err := service.IssueForSession(f.ctx, pair.actors[0], session.ID)
	if err != nil || empty.ICEServers == nil || len(empty.ICEServers) != 0 {
		t.Fatalf("unconfigured: %v", err)
	}
	node, err := f.service.CreateRelayNode(f.ctx, f.principal, relayInput(), "relay-create")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make([]relay.Response, 8)
	errs := make([]error, 8)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = service.IssueForSession(f.ctx, pair.actors[0], session.ID)
		}(i)
	}
	wg.Wait()
	for i := range results {
		if errs[i] != nil || len(results[i].ICEServers) != 1 {
			t.Fatalf("concurrent issuance %d: %v", i, errs[i])
		}
		if results[i].ICEServers[0].Username != results[0].ICEServers[0].Username {
			t.Fatal("concurrent issuance did not reuse")
		}
	}
	var receipts, charged, audits int
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM relay_issuances").Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if err = f.pool.QueryRow(f.ctx, "SELECT sum(issued) FROM relay_issuance_windows").Scan(&charged); err != nil {
		t.Fatal(err)
	}
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM audit_events WHERE action='relay.issue'").Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if receipts != 1 || charged != 3 || audits != 1 {
		t.Fatalf("receipt/quota/audit: %d/%d/%d", receipts, charged, audits)
	}
	restarted, err := relay.NewService(f.pool, issuer, pair.auth, relay.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	again, err := restarted.IssueForSession(f.ctx, pair.actors[0], session.ID)
	if err != nil || again.ICEServers[0].Username != results[0].ICEServers[0].Username {
		t.Fatalf("restart reuse: %v", err)
	}
	limits := relay.DefaultLimits()
	limits.DevicePerMinute = 1
	limited, err := relay.NewService(f.pool, issuer, pair.auth, limits)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.service.UpdateRelayNode(f.ctx, f.principal, node.ID, RelayNodeUpdate{Name: ptr("new revision")}, "revision-change")
	if err != nil {
		t.Fatal(err)
	}
	_, err = limited.IssueForSession(f.ctx, pair.actors[0], session.ID)
	var domain *relay.Error
	if !errors.As(err, &domain) || domain.Code != "RELAY_ISSUANCE_LIMIT" {
		t.Fatalf("persistent limit: %v", err)
	}
	handler := relay.NewHandler(service, pair.store)
	req := httptest.NewRequest("GET", "/v1/device-sessions/"+session.ID+"/ice-servers", nil)
	req.Header.Set("Authorization", "Bearer "+pair.credentials[0].DeviceCredential)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != 200 || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("device route: %d", response.Code)
	}
	req.Header.Set("Authorization", "Bearer "+f.credential.ServiceCredential)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if response.Code != 401 {
		t.Fatalf("service audience: %d", response.Code)
	}
	if _, err = f.service.RevokeConnectionGrant(f.ctx, f.principal, pair.grant.ID, "revoke-relay-grant"); err != nil {
		t.Fatal(err)
	}
	if _, err = service.IssueForSession(f.ctx, pair.actors[0], session.ID); err == nil {
		t.Fatal("revoked grant reused ICE receipt")
	}
}

func TestRelayRequiresAcceptanceLiveLeaseAndCurrentCredential(t *testing.T) {
	f := setup(t)
	issuer := setupRelay(t, f)
	pair := makePair(t, f)
	if _, err := f.service.CreateRelayNode(f.ctx, f.principal, relayInput(), "relay-create"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.UpdateApplication(f.ctx, f.principal, pair.actors[1].ApplicationID, ApplicationUpdate{RequireTargetApproval: ptr(true)}, "require-approval"); err != nil {
		t.Fatal(err)
	}
	session, err := pair.auth.Request(f.ctx, pair.actors[0], pair.actors[1].ID, "00000000-0000-0000-0000-000000000092")
	if err != nil {
		t.Fatal(err)
	}
	service, err := relay.NewService(f.pool, issuer, pair.auth, relay.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.IssueAuthenticated(f.ctx, pair.actors[0], session.ID, pair.credentials[0].DeviceCredential); err == nil {
		t.Fatal("pending target approval received TURN credentials")
	}
	if _, err = pair.auth.Respond(f.ctx, pair.actors[1], session.ID, true); err != nil {
		t.Fatal(err)
	}
	value, err := service.IssueAuthenticated(f.ctx, pair.actors[0], session.ID, pair.credentials[0].DeviceCredential)
	if err != nil || len(value.ICEServers) != 1 {
		t.Fatalf("accepted issuance: %v", err)
	}
	outsider := pair.actors[0]
	outsider.ID = "00000000-0000-0000-0000-000000000099"
	if _, err = service.IssueForSession(f.ctx, outsider, session.ID); err == nil {
		t.Fatal("nonparticipant issued")
	}
	outsider = pair.actors[0]
	outsider.TenantID = "00000000-0000-0000-0000-000000000099"
	if _, err = service.IssueForSession(f.ctx, outsider, session.ID); err == nil {
		t.Fatal("foreign tenant issued")
	}
	// A previously authenticated Device is insufficient after individual bearer revocation.
	if _, err = f.pool.Exec(f.ctx, "UPDATE device_credentials SET revoked_at=clock_timestamp() WHERE device_id=$1", pair.actors[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err = service.IssueAuthenticated(f.ctx, pair.actors[0], session.ID, pair.credentials[0].DeviceCredential); err == nil {
		t.Fatal("stale authenticated identity replayed after bearer revocation")
	}
	if _, err = f.pool.Exec(f.ctx, "UPDATE sessions SET source_lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", session.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = service.IssueAuthenticated(f.ctx, pair.actors[1], session.ID, pair.credentials[1].DeviceCredential); err == nil {
		t.Fatal("one expired peer lease admitted ICE")
	}
}

func TestSharedRelayOperatorCannotAdoptTenantNode(t *testing.T) {
	f := setup(t)
	issuer := setupRelay(t, f)
	node, err := f.service.CreateRelayNode(f.ctx, f.principal, relayInput(), "tenant-node")
	if err != nil {
		t.Fatal(err)
	}
	input := relay.SharedNodeInput{ID: node.ID, Name: "shared", Endpoint: "turn:shared.example.com:3478?transport=udp", SecretRef: "shared-v1", Enabled: true}
	if err = relay.SetSharedNode(f.ctx, f.pool, issuer, input); err == nil {
		t.Fatal("operator adopted existing tenant node")
	}
	input.ID = "00000000-0000-0000-0000-000000000094"
	if err = relay.SetSharedNode(f.ctx, f.pool, issuer, input); err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.GetRelayNode(f.ctx, f.principal, input.ID); err == nil {
		t.Fatal("tenant managed shared node")
	}
	pair := makePair(t, f)
	session, err := pair.auth.Request(f.ctx, pair.actors[0], pair.actors[1].ID, "00000000-0000-0000-0000-000000000093")
	if err != nil {
		t.Fatal(err)
	}
	service, err := relay.NewService(f.pool, issuer, pair.auth, relay.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	response, err := service.IssueForSession(f.ctx, pair.actors[0], session.ID)
	if err != nil || len(response.ICEServers) != 2 {
		t.Fatalf("tenant plus approved shared nodes: %v", err)
	}
	input.Enabled = false
	if err = relay.SetSharedNode(f.ctx, f.pool, issuer, input); err != nil {
		t.Fatal(err)
	}
	response, err = service.IssueForSession(f.ctx, pair.actors[0], session.ID)
	if err != nil || len(response.ICEServers) != 1 {
		t.Fatalf("disabled shared node cache survived: %v", err)
	}
}

func TestRelayBearerRevocationWaitsBeforeCachedIssuance(t *testing.T) {
	f := setup(t)
	issuer := setupRelay(t, f)
	pair := makePair(t, f)
	if _, err := f.service.CreateRelayNode(f.ctx, f.principal, relayInput(), "relay-create"); err != nil {
		t.Fatal(err)
	}
	session, err := pair.auth.Request(f.ctx, pair.actors[0], pair.actors[1].ID, "00000000-0000-0000-0000-000000000095")
	if err != nil {
		t.Fatal(err)
	}
	service, err := relay.NewService(f.pool, issuer, pair.auth, relay.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.IssueAuthenticated(f.ctx, pair.actors[0], session.ID, pair.credentials[0].DeviceCredential); err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(tx)
	if _, err = tx.Exec(f.ctx, "UPDATE device_credentials SET revoked_at=clock_timestamp() WHERE device_id=$1", pair.actors[0].ID); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := service.IssueAuthenticated(f.ctx, pair.actors[0], session.ID, pair.credentials[0].DeviceCredential)
		done <- err
	}()
	select {
	case err = <-done:
		t.Fatalf("issuance did not wait for credential revocation transaction: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err == nil {
		t.Fatal("cached credential issued after revocation committed")
	}
	var count int
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM audit_events WHERE action='relay.issue'").Scan(&count); err != nil || count != 1 {
		t.Fatalf("denied cache hit issued again: %d %v", count, err)
	}
}

func TestRelayExpiryDuringIssuanceRollsBackAllWrites(t *testing.T) {
	for _, expiry := range []string{"lease", "credential"} {
		t.Run(expiry, func(t *testing.T) {
			f := setup(t)
			issuer := setupRelay(t, f)
			pair := makePair(t, f)
			if _, err := f.service.CreateRelayNode(f.ctx, f.principal, relayInput(), "relay-create"); err != nil {
				t.Fatal(err)
			}
			session, err := pair.auth.Request(f.ctx, pair.actors[0], pair.actors[1].ID, "00000000-0000-0000-0000-000000000096")
			if err != nil {
				t.Fatal(err)
			}
			service, err := relay.NewService(f.pool, issuer, pair.auth, relay.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			// Test-only database delay occurs strictly after the initial authorization and
			// quota checks. Elapsed assertion proves we entered this insert, not early deny.
			if _, err = f.pool.Exec(f.ctx, `CREATE FUNCTION delay_relay_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(1); RETURN NEW; END $$;
 CREATE TRIGGER relay_expiry_barrier BEFORE INSERT ON relay_issuances FOR EACH ROW EXECUTE FUNCTION delay_relay_insert()`); err != nil {
				t.Fatal(err)
			}
			if expiry == "lease" {
				_, err = f.pool.Exec(f.ctx, "UPDATE sessions SET source_lease_expires_at=clock_timestamp()+interval '500 milliseconds' WHERE id=$1", session.ID)
			} else {
				_, err = f.pool.Exec(f.ctx, "UPDATE device_credentials SET expires_at=clock_timestamp()+interval '500 milliseconds' WHERE device_id=$1", pair.actors[0].ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			_, err = service.IssueAuthenticated(f.ctx, pair.actors[0], session.ID, pair.credentials[0].DeviceCredential)
			if err == nil {
				t.Fatal("expired authority committed issuance")
			}
			if time.Since(started) < 900*time.Millisecond {
				t.Fatal("test did not reach post-authorization insert barrier")
			}
			var records int
			if err = f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM relay_issuances)+(SELECT count(*) FROM relay_issuance_windows)+(SELECT count(*) FROM audit_events WHERE action='relay.issue')`).Scan(&records); err != nil || records != 0 {
				t.Fatalf("expired transaction left receipt/quota/audit records: %d %v", records, err)
			}
		})
	}
}
