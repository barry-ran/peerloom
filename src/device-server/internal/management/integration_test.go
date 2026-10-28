//go:build integration

package management

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/identity"
	"github.com/barry-ran/peerloom/src/device-server/internal/migrate"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type fixture struct {
	service    *Service
	pool       *pgxpool.Pool
	ctx        context.Context
	key        []byte
	credential KeyResult
	principal  Principal
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
	schema := "peerloom_management_" + hex.EncodeToString(random)
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
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		t.Fatal(err)
	}
	service, err := New(pool, key, DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := BootstrapKey(ctx, pool, "测试租户", ScopeAdmin, time.Hour, "integration")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := service.Authenticate(ctx, credential.ServiceCredential)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{service: service, pool: pool, ctx: ctx, key: key, credential: credential, principal: principal}
}

func requireCode(t *testing.T, err error, want string) {
	t.Helper()
	var public *Error
	if !errors.As(err, &public) || public.Code != want {
		t.Fatalf("expected %s, got %v", want, err)
	}
}

func TestServiceKeysScopesAndTenantIsolation(t *testing.T) {
	f := setup(t)
	app, err := f.service.CreateApplication(f.ctx, f.principal, ApplicationInput{Name: "源应用"}, "application-create-one")
	if err != nil {
		t.Fatal(err)
	}
	readKey, err := IssueKey(f.ctx, f.pool, f.principal.TenantID(), ScopeRead, time.Hour, "reader")
	if err != nil {
		t.Fatal(err)
	}
	read, err := f.service.Authenticate(f.ctx, readKey.ServiceCredential)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.ListApplications(f.ctx, read, Page{}); err != nil {
		t.Fatal(err)
	}
	_, err = f.service.CreateApplication(f.ctx, read, ApplicationInput{Name: "forbidden"}, "read-cannot-create")
	requireCode(t, err, "SCOPE_REQUIRED")
	_, err = f.service.IssueRegistrationGrant(f.ctx, read, RegistrationGrantInput{ApplicationID: app.ID}, "read-cannot-issue")
	requireCode(t, err, "SCOPE_REQUIRED")
	otherKey, err := BootstrapKey(f.ctx, f.pool, "隔离租户", ScopeAdmin, time.Hour, "other")
	if err != nil {
		t.Fatal(err)
	}
	other, err := f.service.Authenticate(f.ctx, otherKey.ServiceCredential)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.service.GetApplication(f.ctx, other, app.ID)
	requireCode(t, err, "APPLICATION_NOT_FOUND")
	_, err = f.service.IssueRegistrationGrant(f.ctx, other, RegistrationGrantInput{ApplicationID: app.ID}, "cross-tenant-grant")
	requireCode(t, err, "APPLICATION_NOT_FOUND")
	err = RevokeKey(f.ctx, f.pool, other.TenantID(), readKey.CredentialID)
	requireCode(t, err, "SERVICE_KEY_NOT_FOUND")
	if err = RevokeKey(f.ctx, f.pool, read.TenantID(), read.CredentialID()); err != nil {
		t.Fatal(err)
	}
	_, err = f.service.Authenticate(f.ctx, readKey.ServiceCredential)
	requireCode(t, err, "SERVICE_AUTH_INVALID")
	_, err = f.service.ListApplications(f.ctx, read, Page{})
	requireCode(t, err, "SERVICE_AUTH_INVALID")
	deviceStore, err := identity.New(f.pool, f.key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = deviceStore.Authenticate(f.ctx, f.credential.ServiceCredential); err == nil {
		t.Fatal("service key accepted as device audience")
	}
}

func TestDurableIdempotencySecretsAndAtomicAudit(t *testing.T) {
	f := setup(t)
	var wg sync.WaitGroup
	apps := make([]Application, 8)
	errs := make([]error, 8)
	for i := range apps {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			apps[i], errs[i] = f.service.CreateApplication(f.ctx, f.principal, ApplicationInput{Name: "幂等应用"}, "same-application-request")
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
		if apps[i].ID != apps[0].ID {
			t.Fatal("concurrent idempotency created duplicate applications")
		}
	}
	input := RegistrationGrantInput{ApplicationID: apps[0].ID}
	grants := make([]RegistrationGrant, 8)
	for i := range grants {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			grants[i], errs[i] = f.service.IssueRegistrationGrant(f.ctx, f.principal, input, "same-registration-grant")
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
		if grants[i].ID != grants[0].ID || grants[i].Grant != grants[0].Grant {
			t.Fatal("concurrent replay minted different secrets")
		}
	}
	freshPool, err := pgxpool.NewWithConfig(f.ctx, f.pool.Config())
	if err != nil {
		t.Fatal(err)
	}
	defer freshPool.Close()
	restarted, err := New(freshPool, f.key, DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	principal, err := restarted.Authenticate(f.ctx, f.credential.ServiceCredential)
	if err != nil {
		t.Fatal(err)
	}
	again, err := restarted.IssueRegistrationGrant(f.ctx, principal, input, "same-registration-grant")
	if err != nil || again.Grant != grants[0].Grant {
		t.Fatal("restart lost durable secret replay", err)
	}
	wrongKey := bytes.Repeat([]byte{42}, 32)
	wrongStore, _ := New(f.pool, wrongKey, DefaultSettings())
	_, err = wrongStore.IssueRegistrationGrant(f.ctx, f.principal, input, "same-registration-grant")
	requireCode(t, err, "REPLAY_UNAVAILABLE")
	_, err = f.service.CreateApplication(f.ctx, f.principal, ApplicationInput{Name: "different"}, "same-application-request")
	requireCode(t, err, "IDEMPOTENCY_CONFLICT")
	var count int
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM applications").Scan(&count); err != nil || count != 1 {
		t.Fatal("unexpected application count")
	}
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM registration_grants").Scan(&count); err != nil || count != 1 {
		t.Fatal("unexpected grant count")
	}
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM audit_events WHERE action IN('application.create','registration_grant.issue')").Scan(&count); err != nil || count != 2 {
		t.Fatal("audit not atomic/idempotent")
	}
	var details string
	if err = f.pool.QueryRow(f.ctx, "SELECT string_agg(details::text,'') FROM audit_events").Scan(&details); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(details, grants[0].Grant) || strings.Contains(details, f.credential.ServiceCredential) {
		t.Fatal("audit leaked credentials")
	}
	var ciphertext []byte
	if err = f.pool.QueryRow(f.ctx, "SELECT response_ciphertext FROM management_requests WHERE operation='registration_grant.issue'").Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte(grants[0].Grant)) {
		t.Fatal("replay stores plaintext secret")
	}
}

func TestExpiryPaginationAndRevalidation(t *testing.T) {
	f := setup(t)
	for _, name := range []string{"one", "two", "three"} {
		if _, err := f.service.CreateApplication(f.ctx, f.principal, ApplicationInput{Name: name}, "create-application-"+name); err != nil {
			t.Fatal(err)
		}
	}
	first, err := f.service.ListApplications(f.ctx, f.principal, Page{Limit: 2})
	if err != nil || len(first.Items) != 2 || first.NextCursor == "" {
		t.Fatal("first page invalid", err)
	}
	second, err := f.service.ListApplications(f.ctx, f.principal, Page{Limit: 2, Cursor: first.NextCursor})
	if err != nil || len(second.Items) != 1 || second.NextCursor != "" || second.Items[0].ID == first.Items[0].ID {
		t.Fatal("keyset continuation invalid", err)
	}
	if _, err = f.pool.Exec(f.ctx, "UPDATE management_requests SET response_expires_at=clock_timestamp()-interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	if err = f.service.PurgeExpired(f.ctx); err != nil {
		t.Fatal(err)
	}
	_, err = f.service.CreateApplication(f.ctx, f.principal, ApplicationInput{Name: "one"}, "create-application-one")
	requireCode(t, err, "REPLAY_EXPIRED")
	if _, err = f.pool.Exec(f.ctx, "UPDATE tenant_service_credentials SET scope='read' WHERE id=$1", f.principal.CredentialID()); err != nil {
		t.Fatal(err)
	}
	_, err = f.service.CreateApplication(f.ctx, f.principal, ApplicationInput{Name: "downgraded"}, "downgraded-scope-request")
	requireCode(t, err, "SCOPE_REQUIRED")
	if _, err = f.pool.Exec(f.ctx, "UPDATE tenants SET status='suspended' WHERE id=$1", f.principal.TenantID()); err != nil {
		t.Fatal(err)
	}
	_, err = f.service.Authenticate(f.ctx, f.credential.ServiceCredential)
	requireCode(t, err, "SERVICE_AUTH_INVALID")
}

func TestManagementHTTPUsesServiceAudience(t *testing.T) {
	f := setup(t)
	handler := NewHandler(f.service)
	request := func(method, path, body, credential string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+credential)
		r.Header.Set("Idempotency-Key", "http-management-request")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if w := request("GET", "/v1/applications", "", "dev_"+strings.Repeat("a", 43)); w.Code != 401 {
		t.Fatal("device audience admitted by management HTTP")
	}
	w := request("POST", "/v1/applications", `{"name":"HTTP应用","tenant_id":"injected"}`, f.credential.ServiceCredential)
	if w.Code != 422 {
		t.Fatal("unknown tenant claim accepted")
	}
	w = request("POST", "/v1/applications", `{"name":"HTTP应用"}`, f.credential.ServiceCredential)
	if w.Code != 201 {
		t.Fatalf("application HTTP status %d", w.Code)
	}
	var application Application
	if err := json.Unmarshal(w.Body.Bytes(), &application); err != nil {
		t.Fatal(err)
	}
	w = request("GET", "/v1/applications/"+application.ID, "", f.credential.ServiceCredential)
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("management HTTP retrieval failed")
	}
}
