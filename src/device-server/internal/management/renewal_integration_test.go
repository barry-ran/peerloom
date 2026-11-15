//go:build integration

package management

import (
	"bytes"
	"encoding/json"
	"github.com/barry-ran/peerloom/src/device-server/internal/migrate"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestRenewalSingleSuccessorAndStableReplay(t *testing.T) {
	f := renewalFixture(t)
	app, err := f.service.CreateApplication(f.ctx, f.principal, ApplicationInput{Name: "stable"}, "original-operation-7fa80ae8624b448ea9d85a3d0ac1ccaa")
	if err != nil {
		t.Fatal(err)
	}
	const op = "7fa80ae8-624b-448e-a9d8-5a3d0ac1ccaa"
	var wg sync.WaitGroup
	out := make([]ServiceKeyRenewal, 5)
	errs := make([]error, 5)
	for i := range out {
		wg.Add(1)
		go func(i int) { defer wg.Done(); out[i], errs[i] = f.service.RenewServiceKey(f.ctx, f.principal, op) }(i)
	}
	wg.Wait()
	for i := range out {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		if out[i].ServiceCredential != out[0].ServiceCredential || out[i].CredentialID != out[0].CredentialID {
			t.Fatal("branched renewal")
		}
	}
	r := out[0]
	if r.SubjectID != f.credential.CredentialID || r.CredentialID == r.SubjectID || r.Scope != ScopeAdmin {
		t.Fatal("identity or scope changed")
	}
	if r.PreviousAcceptUntil.After(f.credential.ExpiresAt) {
		t.Fatal("extended predecessor lifetime")
	}
	next, err := f.service.Authenticate(f.ctx, r.ServiceCredential)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := f.service.CreateApplication(f.ctx, next, ApplicationInput{Name: "stable"}, "original-operation-7fa80ae8624b448ea9d85a3d0ac1ccaa")
	if err != nil || replay.ID != app.ID {
		t.Fatalf("cross-key replay failed: %v", err)
	}
	_, err = f.service.RenewServiceKey(f.ctx, f.principal, "different-operation-7fa80ae8624b448ea9d85a3d0ac1ccaa")
	requireCode(t, err, "RENEWAL_ALREADY_EXISTS")
	_, err = f.service.RenewServiceKey(f.ctx, next, "early-generation-7fa80ae8624b448ea9d85a3d0ac1ccaa")
	requireCode(t, err, "RENEWAL_TOO_EARLY")
	var count int
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM tenant_service_credentials WHERE subject_id=$1", r.SubjectID).Scan(&count); err != nil || count != 2 {
		t.Fatalf("expected 2 keys: %d %v", count, err)
	}
	if err = RevokeKey(f.ctx, f.pool, f.principal.TenantID(), f.principal.CredentialID()); err != nil {
		t.Fatal(err)
	}
	_, err = f.service.RenewServiceKey(f.ctx, f.principal, op)
	requireCode(t, err, "SERVICE_AUTH_INVALID")
	if _, err = f.service.ServiceKeySelf(f.ctx, next); err != nil {
		t.Fatal("old revoke disabled successor", err)
	}
	if err = RevokeSubject(f.ctx, f.pool, next.TenantID(), next.SubjectID()); err != nil {
		t.Fatal(err)
	}
	_, err = f.service.ServiceKeySelf(f.ctx, next)
	requireCode(t, err, "SERVICE_AUTH_INVALID")
}

func TestRenewalAuthorityAndExpiredRecovery(t *testing.T) {
	f := renewalFixture(t)
	readKey, err := IssueKey(f.ctx, f.pool, f.principal.TenantID(), ScopeRead, time.Hour, "reader")
	if err != nil {
		t.Fatal(err)
	}
	if err = SetSubjectRenewal(f.ctx, f.pool, readKey.TenantID, readKey.SubjectID, true); err != nil {
		t.Fatal(err)
	}
	p, err := f.service.Authenticate(f.ctx, readKey.ServiceCredential)
	if err != nil {
		t.Fatal(err)
	}
	r, err := f.service.RenewServiceKey(f.ctx, p, "reader-operation-7fa80ae8624b448ea9d85a3d0ac1ccaa")
	if err != nil {
		t.Fatal(err)
	}
	if r.Scope != ScopeRead || r.SubjectID == f.principal.SubjectID() {
		t.Fatal("scope/subject escaped")
	}
	if _, err = f.pool.Exec(f.ctx, "UPDATE service_key_renewals SET replay_until=clock_timestamp()-interval '1 second' WHERE previous_credential_id=$1", p.CredentialID()); err != nil {
		t.Fatal(err)
	}
	_, err = f.service.RenewServiceKey(f.ctx, p, "reader-operation-7fa80ae8624b448ea9d85a3d0ac1ccaa")
	requireCode(t, err, "RENEWAL_UNAVAILABLE")
	if _, err = f.pool.Exec(f.ctx, "UPDATE tenant_service_credentials SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", p.CredentialID()); err != nil {
		t.Fatal(err)
	}
	_, err = f.service.RenewServiceKey(f.ctx, p, "reader-operation-7fa80ae8624b448ea9d85a3d0ac1ccaa")
	requireCode(t, err, "SERVICE_AUTH_INVALID")
	_, err = f.service.RenewServiceKey(f.ctx, Principal{browser: &BrowserIdentity{}}, "browser-operation-7fa80ae8624b448ea9d85a3d0ac1ccaa")
	requireCode(t, err, "SERVICE_AUTH_REQUIRED")
}

func TestRenewalHTTPContractAndNoScopeOverride(t *testing.T) {
	f := renewalFixture(t)
	h := NewHandler(f.service)
	req := httptest.NewRequest(http.MethodPost, "/v1/service-credentials/renew", bytes.NewBufferString("{}"))
	req.Header.Set("Authorization", "Bearer "+f.credential.ServiceCredential)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "http-contract-operation-7fa80ae8624b448ea9d85a3d0ac1ccaa")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var r ServiceKeyRenewal
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.EffectiveAcceptUntil.IsZero() || r.RenewAfter.IsZero() || r.SubjectID == "" || r.ServiceCredential == "" {
		t.Fatal("missing response metadata")
	}
	req = httptest.NewRequest(http.MethodPost, "/v1/service-credentials/renew", bytes.NewBufferString(`{"scope-7fa80ae8624b448ea9d85a3d0ac1ccaa":"admin"}`))
	req.Header.Set("Authorization", "Bearer "+r.ServiceCredential)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "cannot-override-scope-7fa80ae8624b448ea9d85a3d0ac1ccaa")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 400 && w.Code != 422 {
		t.Fatal("unexpected override response", w.Code)
	}
}

func TestRenewalRollbackAndRevokedSuccessor(t *testing.T) {
	f := renewalFixture(t)
	_, err := f.service.RenewServiceKeyPersisted(f.ctx, f.principal, "persist-failure-operation-7fa80ae8624b448ea9d85a3d0ac1ccaa", func(ServiceKeyRenewal) error { return fail("TEST_PERSIST", 500) })
	requireCode(t, err, "TEST_PERSIST")
	var count int
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM service_key_renewals").Scan(&count); err != nil || count != 0 {
		t.Fatal("failed persistence committed")
	}
	r, err := f.service.RenewServiceKey(f.ctx, f.principal, "persist-failure-operation-7fa80ae8624b448ea9d85a3d0ac1ccaa")
	if err != nil {
		t.Fatal(err)
	}
	if err = RevokeKey(f.ctx, f.pool, r.TenantID, r.CredentialID); err != nil {
		t.Fatal(err)
	}
	_, err = f.service.RenewServiceKey(f.ctx, f.principal, "persist-failure-operation-7fa80ae8624b448ea9d85a3d0ac1ccaa")
	requireCode(t, err, "RENEWAL_UNAVAILABLE")
}

func TestLegacySchemaReplaySurvivesSubjectMigrationAndRenewal(t *testing.T) {
	f := renewalFixture(t)
	app, err := f.service.CreateApplication(f.ctx, f.principal, ApplicationInput{Name: "legacy-v1"}, "legacy-operation-7fa80ae8624b448ea9d85a3d0ac1ccaa")
	if err != nil {
		t.Fatal(err)
	}
	dir, err := filepath.Abs("../../../../infra/migrations")
	if err != nil {
		t.Fatal(err)
	}
	migrations, err := migrate.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	for version := len(migrations); version >= 12; version-- {
		if err = migrate.Apply(f.ctx, f.pool, migrations, "down"); err != nil {
			t.Fatal(err)
		}
	}
	var oldID string
	var before []byte
	if err = f.pool.QueryRow(f.ctx, "SELECT service_credential_id::text,response_ciphertext FROM management_requests WHERE operation='application.create'").Scan(&oldID, &before); err != nil {
		t.Fatal(err)
	}
	// Schema 11 identifies the encrypted v1 receipt by its actual credential.
	if oldID != f.principal.CredentialID() {
		t.Fatal("not legacy credential identity")
	}
	if err = migrate.Apply(f.ctx, f.pool, migrations, "up"); err != nil {
		t.Fatal(err)
	}
	var after []byte
	if err = f.pool.QueryRow(f.ctx, "SELECT response_ciphertext FROM management_requests WHERE service_subject_id=$1", oldID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("migration rewrote encrypted receipt")
	}
	if err = SetSubjectRenewal(f.ctx, f.pool, f.credential.TenantID, f.credential.SubjectID, true); err != nil {
		t.Fatal(err)
	}
	p, err := f.service.Authenticate(f.ctx, f.credential.ServiceCredential)
	if err != nil {
		t.Fatal(err)
	}
	r, err := f.service.RenewServiceKey(f.ctx, p, "legacy-renewal-operation-7fa80ae8624b448ea9d85a3d0ac1ccaa")
	if err != nil {
		t.Fatal(err)
	}
	next, err := f.service.Authenticate(f.ctx, r.ServiceCredential)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := f.service.CreateApplication(f.ctx, next, ApplicationInput{Name: "legacy-v1"}, "legacy-operation-7fa80ae8624b448ea9d85a3d0ac1ccaa")
	if err != nil || replay.ID != app.ID {
		t.Fatalf("old ciphertext not decryptable by successor: %v", err)
	}
	for version := len(migrations); version > 12; version-- {
		if err = migrate.Apply(f.ctx, f.pool, migrations, "down"); err != nil {
			t.Fatal(err)
		}
	}
	if err = migrate.Apply(f.ctx, f.pool, migrations, "down"); err == nil {
		t.Fatal("renewed subjects downgrade unexpectedly allowed")
	}
}

func TestRenewalDisabledTenantAndRacingRevocation(t *testing.T) {
	for _, subject := range []bool{false, true} {
		f := renewalFixture(t)
		var wg sync.WaitGroup
		wg.Add(2)
		var renewErr, revokeErr error
		go func() {
			defer wg.Done()
			_, renewErr = f.service.RenewServiceKey(f.ctx, f.principal, "race-renewal-operation-7fa80ae8624b448ea9d85a3d0ac1ccaa")
		}()
		go func() {
			defer wg.Done()
			if subject {
				revokeErr = RevokeSubject(f.ctx, f.pool, f.principal.TenantID(), f.principal.SubjectID())
			} else {
				revokeErr = RevokeKey(f.ctx, f.pool, f.principal.TenantID(), f.principal.CredentialID())
			}
		}()
		wg.Wait()
		if revokeErr != nil {
			t.Fatal(revokeErr)
		}
		if renewErr != nil {
			requireCode(t, renewErr, "SERVICE_AUTH_INVALID")
		}
		_, err := f.service.RenewServiceKey(f.ctx, f.principal, "race-renewal-operation-7fa80ae8624b448ea9d85a3d0ac1ccaa")
		requireCode(t, err, "SERVICE_AUTH_INVALID")
	}
	f := renewalFixture(t)
	r, err := f.service.RenewServiceKey(f.ctx, f.principal, "tenant-disable-operation-7fa80ae8624b448ea9d85a3d0ac1ccaa")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(f.ctx, "UPDATE tenants SET status='suspended' WHERE id=$1", f.principal.TenantID()); err != nil {
		t.Fatal(err)
	}
	_, err = f.service.RenewServiceKey(f.ctx, f.principal, "tenant-disable-operation-7fa80ae8624b448ea9d85a3d0ac1ccaa")
	requireCode(t, err, "SERVICE_AUTH_INVALID")
	_, err = f.service.Authenticate(f.ctx, r.ServiceCredential)
	requireCode(t, err, "SERVICE_AUTH_INVALID")
}

func renewalFixture(t *testing.T) fixture {
	f := setup(t)
	if err := SetSubjectRenewal(f.ctx, f.pool, f.credential.TenantID, f.credential.SubjectID, true); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestRenewalRequiresExplicitOfflineGrantAndDisableBlocksReplay(t *testing.T) {
	f := setup(t)
	const op = "8c2e9f410def4472916fa035301eec4c"
	info, err := f.service.ServiceKeySelf(f.ctx, f.principal)
	if err != nil || info.RenewalEnabled {
		t.Fatal("finite bootstrap implicitly renewable", err)
	}
	_, err = f.service.RenewServiceKey(f.ctx, f.principal, op)
	requireCode(t, err, "RENEWAL_DISABLED")
	if err = SetSubjectRenewal(f.ctx, f.pool, f.credential.TenantID, f.credential.SubjectID, true); err != nil {
		t.Fatal(err)
	}
	r, err := f.service.RenewServiceKey(f.ctx, f.principal, op)
	if err != nil {
		t.Fatal(err)
	}
	if !r.RenewalEnabled {
		t.Fatal("renew metadata missing enabled state")
	}
	if err = SetSubjectRenewal(f.ctx, f.pool, f.credential.TenantID, f.credential.SubjectID, false); err != nil {
		t.Fatal(err)
	}
	_, err = f.service.RenewServiceKey(f.ctx, f.principal, op)
	requireCode(t, err, "RENEWAL_DISABLED")
	if _, err = f.service.Authenticate(f.ctx, r.ServiceCredential); err != nil {
		t.Fatal("disable revoked current key", err)
	}
	if err = RevokeSubject(f.ctx, f.pool, f.credential.TenantID, f.credential.SubjectID); err != nil {
		t.Fatal(err)
	}
	err = SetSubjectRenewal(f.ctx, f.pool, f.credential.TenantID, f.credential.SubjectID, true)
	requireCode(t, err, "SERVICE_SUBJECT_NOT_ACTIVE")
}

func TestRenewalOperationHashIsAuthenticated(t *testing.T) {
	f := renewalFixture(t)
	const original = "57801c17304440faaafcddfa2e6774ac"
	const substituted = "d3e32724dcde48bfaf138124e11a56ad"
	if _, err := f.service.RenewServiceKey(f.ctx, f.principal, original); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, "UPDATE service_key_renewals SET operation_hash=$1 WHERE previous_credential_id=$2", hash(substituted), f.principal.CredentialID()); err != nil {
		t.Fatal(err)
	}
	_, err := f.service.RenewServiceKey(f.ctx, f.principal, substituted)
	requireCode(t, err, "RENEWAL_UNAVAILABLE")
}
