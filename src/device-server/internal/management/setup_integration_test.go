//go:build integration

package management

import (
	"errors"
	"testing"
	"time"
)

func TestSetupEmptyTransactionAndRepeat(t *testing.T) {
	f := setup(t)
	// Fixture owns a random schema. Remove its initial tenant only within it.
	if _, err := f.pool.Exec(f.ctx, "TRUNCATE tenants CASCADE"); err != nil {
		t.Fatal(err)
	}
	if _, err := SetupEmpty(f.ctx, f.pool, "selfhost", "app", time.Hour, func(SetupResult) error { return errors.New("disk failure") }); err == nil {
		t.Fatal("persist failure ignored")
	}
	var count int
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM tenants").Scan(&count); err != nil || count != 0 {
		t.Fatalf("rollback failed count=%d err=%v", count, err)
	}
	var saved SetupResult
	got, err := SetupEmpty(f.ctx, f.pool, "selfhost", "app", time.Hour, func(r SetupResult) error { saved = r; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if got.ApplicationID == "" || saved.ServiceCredential == "" {
		t.Fatal("missing provisioning material")
	}
	p, err := f.service.Authenticate(f.ctx, saved.ServiceCredential)
	if err != nil {
		t.Fatal(err)
	}
	page, err := f.service.ListApplications(f.ctx, p, Page{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != got.ApplicationID || page.Items[0].TenantID != got.TenantID {
		t.Fatal("wrong application mapping")
	}
	if _, err = VerifySetup(f.ctx, f.pool, saved); err != nil {
		t.Fatal(err)
	}
	fake := saved
	fake.ServiceCredential = "svc_invalidmaterial"
	if _, err = VerifySetup(f.ctx, f.pool, fake); err == nil {
		t.Fatal("fake secret accepted")
	}
	var mode string
	if err = f.pool.QueryRow(f.ctx, "SELECT registration_mode FROM applications WHERE id=$1", got.ApplicationID).Scan(&mode); err != nil || mode != "grant" {
		t.Fatal("unsafe registration mode", err)
	}
	called := false
	_, err = SetupEmpty(f.ctx, f.pool, "selfhost", "app", time.Hour, func(SetupResult) error { called = true; return nil })
	requireCode(t, err, "SETUP_ALREADY_INITIALIZED")
	if called {
		t.Fatal("repeat emitted new credential")
	}
	status, err := InspectKey(f.ctx, f.pool, got.TenantID, got.CredentialID)
	if err != nil || status.Expired || !status.TenantActive || status.RevokedAt != nil {
		t.Fatal("bad key status", err)
	}
	if err = RevokeKey(f.ctx, f.pool, got.TenantID, got.CredentialID); err != nil {
		t.Fatal(err)
	}
	status, err = InspectKey(f.ctx, f.pool, got.TenantID, got.CredentialID)
	if err != nil || status.RevokedAt == nil {
		t.Fatal("revocation not reflected", err)
	}
}
func TestIssueKeyPersistenceFailureRollsBack(t *testing.T) {
	f := setup(t)
	var before, after int
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM tenant_service_credentials").Scan(&before)
	_, err := IssueKeyPersisted(f.ctx, f.pool, f.credential.TenantID, ScopeAdmin, time.Hour, "replacement", func(KeyResult) error { return errors.New("disk failed") })
	if err == nil {
		t.Fatal("write error ignored")
	}
	_ = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM tenant_service_credentials").Scan(&after)
	if before != after {
		t.Fatal("credential committed without output")
	}
	if _, err = f.service.Authenticate(f.ctx, f.credential.ServiceCredential); err != nil {
		t.Fatal("old credential disrupted", err)
	}
}

func TestSetupConcurrentAndKeyOverlap(t *testing.T) {
	f := setup(t)
	if _, err := f.pool.Exec(f.ctx, "TRUNCATE tenants CASCADE"); err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		r   SetupResult
		err error
	}
	results := make(chan outcome, 2)
	for i := 0; i < 2; i++ {
		go func() {
			r, err := SetupEmpty(f.ctx, f.pool, "first", "app", time.Hour, func(SetupResult) error { return nil })
			results <- outcome{r, err}
		}()
	}
	var winner SetupResult
	ok := 0
	for i := 0; i < 2; i++ {
		r := <-results
		if r.err == nil {
			ok++
			winner = r.r
		} else {
			requireCode(t, r.err, "SETUP_ALREADY_INITIALIZED")
		}
	}
	if ok != 1 {
		t.Fatal("concurrent setup duplicated")
	}
	next, err := IssueKey(f.ctx, f.pool, winner.TenantID, ScopeAdmin, time.Hour, "rotate")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.Authenticate(f.ctx, winner.ServiceCredential); err != nil {
		t.Fatal("overlap lost")
	}
	if _, err = f.service.Authenticate(f.ctx, next.ServiceCredential); err != nil {
		t.Fatal("new key invalid")
	}
	if err = RevokeKey(f.ctx, f.pool, winner.TenantID, winner.CredentialID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.Authenticate(f.ctx, next.ServiceCredential); err != nil {
		t.Fatal("new key revoked with old")
	}
	if _, err = f.pool.Exec(f.ctx, "UPDATE tenant_service_credentials SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", next.CredentialID); err != nil {
		t.Fatal(err)
	}
	status, err := InspectKey(f.ctx, f.pool, next.TenantID, next.CredentialID)
	if err != nil || !status.Expired {
		t.Fatal("expiry missing", err)
	}
}
