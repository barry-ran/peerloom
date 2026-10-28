//go:build integration

package adminauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"github.com/barry-ran/peerloom/src/device-server/internal/management"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires isolated PostgreSQL")
	}
	ctx := context.Background()
	base, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal("connect test database")
	}
	random := make([]byte, 8)
	_, _ = rand.Read(random)
	schema := "admin_test_" + hex.EncodeToString(random)
	if _, err = base.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal("create isolated schema")
	}
	t.Cleanup(func() { _, _ = base.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE"); base.Close() })
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("parse test DSN")
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal("open isolated schema")
	}
	t.Cleanup(pool.Close)
	files, err := filepath.Glob("../../../../infra/migrations/*.up.sql")
	if err != nil || len(files) != 6 {
		t.Fatal("expected baseline1..5 plus admin6 fixture migrations")
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal("read fixture migration")
		}
		if _, err = pool.Exec(ctx, string(data)); err != nil {
			t.Fatalf("migration %s failed: %v", filepath.Base(file), err)
		}
	}
	return pool
}
func TestBrowserSessionManagementIsolationAndRevocation(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	var tenant, foreign string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES('admin fixture') RETURNING id::text`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES('foreign fixture') RETURNING id::text`).Scan(&foreign); err != nil {
		t.Fatal(err)
	}
	const password = "Synthetic local-only passphrase 123!"
	user, err := CreateUser(ctx, pool, tenant, "owner", password, management.ScopeAdmin)
	if err != nil {
		t.Fatal(err)
	}
	_, err = CreateUser(ctx, pool, tenant, "reader", password, management.ScopeRead)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := New(pool)
	if err != nil {
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
	server := httptest.NewUnstartedServer(nil)
	origin := "http://" + server.Listener.Addr().String()
	handler, err := NewHandler(auth, management.NewHandler(backend), HTTPConfig{Origin: origin, DevelopmentLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = handler
	server.Start()
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	var cookie *http.Cookie
	csrf := ""
	call := func(method, path string, body any, csrfHeader bool) (int, map[string]any, []*http.Cookie) {
		t.Helper()
		encoded, _ := json.Marshal(body)
		request, _ := http.NewRequest(method, origin+path, strings.NewReader(string(encoded)))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", origin)
		request.Header.Set("Idempotency-Key", "browser-fixture-idempotency")
		if cookie != nil {
			request.AddCookie(cookie)
		}
		if csrfHeader {
			request.Header.Set("X-CSRF-Token", csrf)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("HTTP request failed")
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 65537))
		if err != nil || len(data) > 65536 {
			t.Fatal("bounded response failed")
		}
		if response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("browser response cacheable")
		}
		var value map[string]any
		if json.Unmarshal(data, &value) != nil {
			t.Fatal("JSON response required")
		}
		return response.StatusCode, value, response.Cookies()
	}
	login := func(name string) {
		t.Helper()
		status, value, cookies := call("POST", "/admin/api/auth/login", map[string]string{"tenant_id": tenant, "username": name, "password": password}, false)
		if status != 200 || len(cookies) != 1 {
			t.Fatalf("login status=%d", status)
		}
		cookie = cookies[0]
		csrf = value["csrf_token"].(string)
		if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Secure || len(cookie.Value) != 47 {
			t.Fatal("development cookie policy invalid")
		}
		if _, found := value["Token"]; found {
			t.Fatal("token serialized in body")
		}
	}
	login("owner")
	status, _, _ := call("POST", "/admin/api/v1/applications", map[string]any{"name": "console app", "require_target_approval": true}, false)
	if status != 403 {
		t.Fatalf("missing csrf=%d", status)
	}
	status, created, _ := call("POST", "/admin/api/v1/applications", map[string]any{"name": "console app", "require_target_approval": true}, true)
	if status != 201 {
		t.Fatalf("create=%d", status)
	}
	status, replayed, _ := call("POST", "/admin/api/v1/applications", map[string]any{"name": "console app", "require_target_approval": true}, true)
	if status != 201 || created["id"] != replayed["id"] {
		t.Fatal("browser replay repeated mutation")
	}
	var audit int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE actor_type='admin_user' AND actor_id=$1 AND action='application.create'`, user).Scan(&audit); err != nil || audit != 1 {
		t.Fatal("wrong browser audit identity")
	}
	var foreignApp string
	if err = pool.QueryRow(ctx, `INSERT INTO applications(tenant_id,name,registration_mode) VALUES($1,'foreign','grant') RETURNING id::text`, foreign).Scan(&foreignApp); err != nil {
		t.Fatal(err)
	}
	status, _, _ = call("GET", "/admin/api/v1/applications/"+foreignApp, nil, false)
	if status != 404 {
		t.Fatalf("cross tenant=%d", status)
	}
	oldToken := cookie.Value
	status, _, _ = call("POST", "/admin/api/auth/logout", nil, true)
	if status != 200 {
		t.Fatal("logout failed")
	}
	if _, err = auth.Session(ctx, oldToken); err == nil {
		t.Fatal("logged out cookie remains valid")
	}
	login("reader")
	status, _, _ = call("GET", "/admin/api/v1/applications", nil, false)
	if status != 200 {
		t.Fatal("reader query denied")
	}
	status, _, _ = call("POST", "/admin/api/v1/applications", map[string]any{"name": "forbidden"}, true)
	if status != 403 {
		t.Fatalf("reader mutation=%d", status)
	}
	login("owner")
	oldToken = cookie.Value
	if err = ChangeUser(ctx, pool, tenant, user, "Changed local-only passphrase 456!", "", false); err != nil {
		t.Fatal(err)
	}
	if _, err = auth.Session(ctx, oldToken); err == nil {
		t.Fatal("password reset retained session")
	}
	if _, err = auth.Login(ctx, tenant, "owner", password, "127.0.0.1"); err == nil {
		t.Fatal("old password still works")
	}
}
