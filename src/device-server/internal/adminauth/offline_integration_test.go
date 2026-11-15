//go:build integration

package adminauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/barry-ran/peerloom/src/device-server/internal/management"
	"github.com/jackc/pgx/v5/pgxpool"
)

const offlinePassword = "Synthetic local-only passphrase 123!"

func offlineFixture(t *testing.T) (*pgxpool.Pool, *Service, string, string) {
	t.Helper()
	pool := testPool(t)
	var tenant string
	if err := pool.QueryRow(context.Background(), `INSERT INTO tenants(name) VALUES('offline fixture') RETURNING id::text`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	user, err := CreateUser(context.Background(), pool, tenant, "owner", offlinePassword, management.ScopeAdmin)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := New(pool)
	if err != nil {
		t.Fatal(err)
	}
	return pool, auth, tenant, user
}
func assertProblem(t *testing.T, err error, code string, status int) {
	t.Helper()
	var problem *management.Error
	if !errors.As(err, &problem) || problem.Code != code || problem.Status != status {
		t.Fatalf("expected %s/%d, got %v", code, status, err)
	}
}
func TestOfflineDisableEnableAndReset(t *testing.T) {
	pool, auth, tenant, user := offlineFixture(t)
	ctx := context.Background()
	login, err := auth.Login(ctx, tenant, "owner", offlinePassword, "fixture-ip")
	if err != nil {
		t.Fatal(err)
	}
	if err = ChangeUser(ctx, pool, strings.ToUpper(tenant), user, "", "", true); err != nil {
		t.Fatal(err)
	}
	_, err = auth.Session(ctx, login.Token)
	assertProblem(t, err, "ADMIN_AUTH_INVALID", 401)
	_, err = auth.Login(ctx, tenant, "owner", offlinePassword, "fixture-ip")
	assertProblem(t, err, "AUTH_INVALID", 401)
	enabled := true
	if err = UpdateUser(ctx, pool, tenant, user, UserChange{Enabled: &enabled}); err != nil {
		t.Fatal(err)
	}
	_, err = auth.Session(ctx, login.Token)
	assertProblem(t, err, "ADMIN_AUTH_INVALID", 401)
	login, err = auth.Login(ctx, tenant, "owner", offlinePassword, "fixture-ip")
	if err != nil {
		t.Fatal(err)
	}
	if err = UpdateUser(ctx, pool, tenant, user, UserChange{Scope: management.ScopeRead}); err != nil {
		t.Fatal(err)
	}
	_, err = auth.Session(ctx, login.Token)
	assertProblem(t, err, "ADMIN_AUTH_INVALID", 401)
	if err = UpdateUser(ctx, pool, tenant, user, UserChange{Password: "New synthetic offline passphrase!"}); err != nil {
		t.Fatal(err)
	}
	_, err = auth.Login(ctx, tenant, "owner", offlinePassword, "fixture-ip")
	assertProblem(t, err, "AUTH_INVALID", 401)
	login, err = auth.Login(ctx, tenant, "owner", "New synthetic offline passphrase!", "fixture-ip")
	if err != nil {
		t.Fatal(err)
	}
	if login.Session.Scope != management.ScopeRead {
		t.Fatal("role change lost")
	}
	assertProblem(t, UpdateUser(ctx, pool, tenant, user, UserChange{}), "INVALID_ADMIN_USER", 422)
	assertProblem(t, UpdateUser(ctx, pool, "11111111-1111-4111-8111-111111111111", user, UserChange{Enabled: &enabled}), "ADMIN_USER_NOT_FOUND", 404)
}
func TestLoginSessionCapAndUnknownUser(t *testing.T) {
	pool, auth, tenant, _ := offlineFixture(t)
	ctx := context.Background()
	var tokens []string
	for i := 0; i < 11; i++ {
		// Session retention and login rate limiting are separate controls. This
		// isolated fixture clears only its rate counters to exercise the eleventh session.
		if _, err := pool.Exec(ctx, "DELETE FROM admin_login_windows"); err != nil {
			t.Fatal(err)
		}
		login, err := auth.Login(ctx, tenant, "owner", offlinePassword, "fixture-ip")
		if err != nil {
			t.Fatal(err)
		}
		tokens = append(tokens, login.Token)
	}
	_, err := auth.Session(ctx, tokens[0])
	assertProblem(t, err, "ADMIN_AUTH_INVALID", 401)
	for _, token := range tokens[1:] {
		if _, err = auth.Session(ctx, token); err != nil {
			t.Fatal("retained session invalid")
		}
	}
	for _, name := range []string{"owner", "unknown", "!invalid"} {
		_, err = auth.Login(ctx, tenant, name, "Wrong synthetic passphrase!", "fixture-ip")
		assertProblem(t, err, "AUTH_INVALID", 401)
	}
}
func TestLoginRateLimits(t *testing.T) {
	for _, tc := range []struct {
		name  string
		limit int
	}{{"user", 10}, {"ip", 30}, {"global", 120}} {
		t.Run(tc.name, func(t *testing.T) {
			pool := testPool(t)
			auth := &Service{pool: pool}
			ctx := context.Background()
			// Test only: keep exact threshold assertions in one deterministic window.
			// Each subtest owns its schema; production uses the database clock unchanged.
			if _, err := pool.Exec(ctx, `CREATE FUNCTION fixture_login_window() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.window_start := '2000-01-01 00:00:00+00'::timestamptz; RETURN NEW; END $$;
CREATE TRIGGER fixture_login_window BEFORE INSERT ON admin_login_windows FOR EACH ROW EXECUTE FUNCTION fixture_login_window()`); err != nil {
				t.Fatal(err)
			}
			for i := 0; i <= tc.limit; i++ {
				user, ip := "owner", "fixture-ip"
				if tc.name != "user" {
					user = fmt.Sprintf("user%d", i)
				}
				if tc.name == "global" {
					ip = fmt.Sprintf("ip%d", i)
				}
				err := auth.limit(ctx, "fixture-tenant", user, ip)
				if i == tc.limit {
					assertProblem(t, err, "LOGIN_LIMITED", 429)
				} else if err != nil {
					t.Fatalf("attempt %d: %v", i, err)
				}
			}
			if _, err := pool.Exec(ctx, `CREATE OR REPLACE FUNCTION fixture_login_window() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.window_start := '2000-01-01 00:01:00+00'::timestamptz; RETURN NEW; END $$`); err != nil {
				t.Fatal(err)
			}
			if err := auth.limit(ctx, "fixture-tenant", "owner", "fixture-ip"); err != nil {
				t.Fatalf("new minute did not reset limit: %v", err)
			}
		})
	}
}

// No clock trigger here: an actually expired database window must not block login.
func TestLoginRateLimitIgnoresPriorDatabaseMinute(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO admin_login_windows(key_hash,window_start,attempts) VALUES($1,date_trunc('minute',clock_timestamp())-interval '1 minute',121)`, digest("global")); err != nil {
		t.Fatal(err)
	}
	auth := &Service{pool: pool}
	if err := auth.limit(ctx, "fixture-tenant", "owner", "fixture-ip"); err != nil {
		t.Fatalf("previous minute incorrectly blocked current window: %v", err)
	}
	var count, newest int
	if err := pool.QueryRow(ctx, `SELECT count(*), (SELECT attempts FROM admin_login_windows WHERE key_hash=$1 ORDER BY window_start DESC LIMIT 1) FROM admin_login_windows WHERE key_hash=$1`, digest("global")).Scan(&count, &newest); err != nil || count != 2 || newest != 1 {
		t.Fatal("database minute boundary evidence mismatch")
	}
}

func TestConcurrentOfflineResetAndDisable(t *testing.T) {
	pool, auth, tenant, user := offlineFixture(t)
	ctx := context.Background()
	old, err := auth.Login(ctx, tenant, "owner", offlinePassword, "fixture-ip")
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, change := range []UserChange{{Password: "Replacement synthetic passphrase!"}, {Enabled: func() *bool { v := false; return &v }()}} {
		wg.Add(1)
		go func(change UserChange) {
			defer wg.Done()
			<-start
			results <- UpdateUser(ctx, pool, tenant, user, change)
		}(change)
	}
	close(start)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err = auth.Session(ctx, old.Token)
	assertProblem(t, err, "ADMIN_AUTH_INVALID", 401)
	for _, password := range []string{offlinePassword, "Replacement synthetic passphrase!"} {
		_, err = auth.Login(ctx, tenant, "owner", password, "fixture-ip")
		assertProblem(t, err, "AUTH_INVALID", 401)
	}
	enabled := true
	if err = UpdateUser(ctx, pool, tenant, user, UserChange{Enabled: &enabled}); err != nil {
		t.Fatal(err)
	}
	_, err = auth.Login(ctx, tenant, "owner", offlinePassword, "fixture-ip")
	assertProblem(t, err, "AUTH_INVALID", 401)
	if _, err = auth.Login(ctx, tenant, "owner", "Replacement synthetic passphrase!", "fixture-ip"); err != nil {
		t.Fatal("concurrent reset was lost")
	}
}

// The identical principal UUID deliberately exists in both namespaces. A shared
// receipt table would replay another audience's resource instead of creating it.
func TestBrowserAndServiceReceiptNamespaces(t *testing.T) {
	pool, auth, tenant, user := offlineFixture(t)
	ctx := context.Background()
	serviceToken, err := randomToken("svc_")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `WITH subject AS (INSERT INTO service_subjects(id,tenant_id,scope,current_credential_id) VALUES($1,$2,'admin',$1) RETURNING id,tenant_id) INSERT INTO tenant_service_credentials(id,subject_id,tenant_id,credential_hash,scope,label,expires_at) SELECT id,id,tenant_id,$3,'admin','fixture',clock_timestamp()+interval '1 hour' FROM subject`, user, tenant, digest(serviceToken)); err != nil {
		t.Fatal(err)
	}
	if _, err = CreateUser(ctx, pool, tenant, "second", offlinePassword, management.ScopeAdmin); err != nil {
		t.Fatal(err)
	}
	backend, err := management.New(pool, []byte(strings.Repeat("k", 32)), management.DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.WithBrowserAuthority(auth)
	if err != nil {
		t.Fatal(err)
	}
	handler := management.NewHandler(backend)
	invoke := func(token string, browser bool) string {
		t.Helper()
		request := httptest.NewRequest("POST", "http://fixture/v1/applications", strings.NewReader(`{"name":"receipt namespace fixture","require_target_approval":true}`))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "same-key-across-audiences")
		response := httptest.NewRecorder()
		if browser {
			handler.ServeBrowserHTTP(response, request, token)
		} else {
			request.Header.Set("Authorization", "Bearer "+token)
			handler.ServeHTTP(response, request)
		}
		if response.Code != 201 {
			t.Fatalf("create status %d", response.Code)
		}
		var app management.Application
		if err := json.Unmarshal(response.Body.Bytes(), &app); err != nil {
			t.Fatal("invalid JSON")
		}
		return app.ID
	}
	first, err := auth.Login(ctx, tenant, "owner", offlinePassword, "fixture-ip")
	if err != nil {
		t.Fatal(err)
	}
	second, err := auth.Login(ctx, tenant, "second", offlinePassword, "fixture-ip")
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, tc := range []struct {
		token   string
		browser bool
	}{{serviceToken, false}, {first.Token, true}, {second.Token, true}} {
		id := invoke(tc.token, tc.browser)
		if ids[id] {
			t.Fatal("cross-principal or cross-audience receipt reuse")
		}
		ids[id] = true
		if invoke(tc.token, tc.browser) != id {
			t.Fatal("same principal failed to replay")
		}
	}
	var serviceCount, browserCount int
	if err = pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM management_requests),(SELECT count(*) FROM admin_management_requests)").Scan(&serviceCount, &browserCount); err != nil {
		t.Fatal(err)
	}
	if serviceCount != 1 || browserCount != 2 {
		t.Fatal("receipt namespaces or idempotency broken")
	}
}
