//go:build integration

package management

import (
	"testing"
	"time"
)

func TestRevokedPrincipalCannotReplayAndRevocationBarrier(t *testing.T) {
	f := setup(t)
	input := ApplicationInput{Name: "before-revoke"}
	if _, err := f.service.CreateApplication(f.ctx, f.principal, input, "replay-before-revoke"); err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(tx)
	// Hold the credential row lock, then start a request with an already-issued
	// Principal. It must wait, recheck the committed revoke, and create nothing.
	if _, err = tx.Exec(f.ctx, "UPDATE tenant_service_credentials SET revoked_at=clock_timestamp() WHERE id=$1", f.principal.CredentialID()); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, callErr := f.service.CreateApplication(f.ctx, f.principal, ApplicationInput{Name: "must-not-exist"}, "blocked-create-request")
		done <- callErr
	}()
	select {
	case err = <-done:
		t.Fatalf("request passed locked revocation barrier: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	requireCode(t, <-done, "SERVICE_AUTH_INVALID")
	_, err = f.service.CreateApplication(f.ctx, f.principal, input, "replay-before-revoke")
	requireCode(t, err, "SERVICE_AUTH_INVALID")
	var count int
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM applications WHERE name='must-not-exist'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("unauthorized mutation committed: %d %v", count, err)
	}
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM audit_events WHERE action='application.create'").Scan(&count); err != nil || count != 1 {
		t.Fatalf("unauthorized audit committed: %d %v", count, err)
	}
}

func TestCiphertextCannotMoveBetweenPrincipals(t *testing.T) {
	f := setup(t)
	input := ApplicationInput{Name: "aad-test"}
	if _, err := f.service.CreateApplication(f.ctx, f.principal, input, "same-replay-key"); err != nil {
		t.Fatal(err)
	}
	second, err := IssueKey(f.ctx, f.pool, f.principal.TenantID(), ScopeAdmin, time.Hour, "second")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := f.service.Authenticate(f.ctx, second.ServiceCredential)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.CreateApplication(f.ctx, principal, input, "same-replay-key"); err != nil {
		t.Fatal(err)
	}
	_, err = f.pool.Exec(f.ctx, `UPDATE management_requests dst SET response_nonce=src.response_nonce,response_ciphertext=src.response_ciphertext
FROM management_requests src WHERE src.service_credential_id=$1 AND dst.service_credential_id=$2
AND src.operation='application.create' AND dst.operation=src.operation`, f.principal.CredentialID(), principal.CredentialID())
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.service.CreateApplication(f.ctx, principal, input, "same-replay-key")
	requireCode(t, err, "REPLAY_UNAVAILABLE")
}

func TestAdministrativeReadsPaginationAndDisable(t *testing.T) {
	f := setup(t)
	pair := makePair(t, f)
	page, err := f.service.ListDevices(f.ctx, f.principal, Page{Limit: 1}, DeviceFilter{})
	if err != nil || len(page.Items) != 1 || page.NextCursor == "" || page.Items[0].Online != nil {
		t.Fatalf("first page: %+v %v", page, err)
	}
	second, err := f.service.ListDevices(f.ctx, f.principal, Page{Limit: 1, Cursor: page.NextCursor}, DeviceFilter{})
	if err != nil || len(second.Items) != 1 || second.Items[0].ID == page.Items[0].ID {
		t.Fatalf("second page: %+v %v", second, err)
	}
	online := true
	_, err = f.service.ListDevices(f.ctx, f.principal, Page{}, DeviceFilter{Online: &online})
	requireCode(t, err, "PRESENCE_UNAVAILABLE")
	withPresence, err := New(f.pool, f.key, DefaultSettings(), onlinePresence{})
	if err != nil {
		t.Fatal(err)
	}
	onlinePage, err := withPresence.ListDevices(f.ctx, f.principal, Page{}, DeviceFilter{Online: &online})
	if err != nil || len(onlinePage.Items) != 2 {
		t.Fatalf("online page: %+v %v", onlinePage, err)
	}
	session, err := pair.auth.Request(f.ctx, pair.actors[0], pair.actors[1].ID, "00000000-0000-0000-0000-000000000006")
	if err != nil {
		t.Fatal(err)
	}
	read, err := f.service.GetSession(f.ctx, f.principal, session.ID)
	if err != nil || read.LeaseGeneration != session.LeaseGeneration {
		t.Fatalf("persisted lease generation mismatch: %d %d %v", read.LeaseGeneration, session.LeaseGeneration, err)
	}
	change, err := f.service.UpdateApplication(f.ctx, f.principal, pair.actors[0].ApplicationID, ApplicationUpdate{Name: ptr("disabled"), MaxConnections: ptr(8), Enabled: ptr(false)}, "disable-application")
	if err != nil || len(change.Sessions) != 1 || change.Sessions[0].ID != session.ID {
		t.Fatalf("disable: %+v %v", change, err)
	}
	if _, err = pair.store.Authenticate(f.ctx, pair.credentials[0].DeviceCredential); err == nil {
		t.Fatal("disabled app credential authenticated")
	}
	sessions, err := f.service.ListSessions(f.ctx, f.principal, Page{})
	if err != nil || len(sessions.Items) != 1 || sessions.Items[0].State != "closed" {
		t.Fatalf("session list: %+v %v", sessions, err)
	}
	grants, err := f.service.ListConnectionGrants(f.ctx, f.principal, Page{})
	if err != nil || len(grants.Items) != 1 {
		t.Fatalf("grant list: %+v %v", grants, err)
	}
	audit, err := f.service.ListAudit(f.ctx, f.principal, Page{Limit: 1})
	if err != nil || len(audit.Items) != 1 || audit.NextCursor == "" {
		t.Fatalf("audit first page: %+v %v", audit, err)
	}
	next, err := f.service.ListAudit(f.ctx, f.principal, Page{Limit: 1, Cursor: audit.NextCursor})
	if err != nil || len(next.Items) != 1 || next.Items[0].ID == audit.Items[0].ID {
		t.Fatalf("audit next page: %+v %v", next, err)
	}
}
