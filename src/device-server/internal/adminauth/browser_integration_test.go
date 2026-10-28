//go:build integration

package adminauth

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/adminweb"
	"github.com/barry-ran/peerloom/src/device-server/internal/management"
)

// TestBrowserConsoleChromium uses real Chromium, PostgreSQL, cookie sessions and
// management transactions. It does not stub fetch or weaken the production CSP.
func TestBrowserConsoleChromium(t *testing.T) {
	if os.Getenv("PEERLOOM_ADMIN_BROWSER_TEST") != "1" {
		t.Skip("requires explicit local browser integration gate")
	}
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Fatal("explicit browser gate requires isolated PostgreSQL")
	}
	pool := testPool(t)
	ctx := context.Background()
	var tenant string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES('Synthetic browser fixture') RETURNING id::text`).Scan(&tenant); err != nil {
		t.Fatal("create browser fixture tenant")
	}
	const password = "Synthetic browser fixture password 123!"
	owner, err := CreateUser(ctx, pool, tenant, "owner", password, management.ScopeAdmin)
	if err != nil {
		t.Fatal("create browser fixture owner")
	}
	if _, err = CreateUser(ctx, pool, tenant, "reader", password, management.ScopeRead); err != nil {
		t.Fatal("create browser fixture reader")
	}
	auth, err := New(pool)
	if err != nil {
		t.Fatal("create browser authentication service")
	}
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		t.Fatal("generate fixture replay key")
	}
	backend, err := management.New(pool, key, management.DefaultSettings())
	if err != nil {
		t.Fatal("create fixture management service")
	}
	backend, err = backend.WithBrowserAuthority(auth)
	if err != nil {
		t.Fatal("connect browser authority")
	}
	server := httptest.NewUnstartedServer(nil)
	origin := "http://" + server.Listener.Addr().String()
	api, err := NewHandler(auth, management.NewHandler(backend), HTTPConfig{Origin: origin, DevelopmentLoopback: true})
	if err != nil {
		server.Close()
		t.Fatal("configure loopback browser handler")
	}
	mux := http.NewServeMux()
	mux.Handle("/admin/api/", api)
	mux.Handle("/admin/", adminweb.Handler())
	server.Config.Handler = mux
	server.Config.ReadHeaderTimeout = 5 * time.Second
	server.Start()
	defer server.Close()

	web, err := filepath.Abs("../../../admin-web")
	if err != nil {
		t.Fatal("resolve browser project")
	}
	commandCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	command := exec.CommandContext(commandCtx, "npm", "test")
	command.Dir = web
	// Browser children have no reason to inherit database passwords or service keys.
	for _, name := range []string{"PATH", "HOME", "TMPDIR", "TMP", "TEMP", "CI", "LANG", "LC_ALL", "LD_LIBRARY_PATH", "PLAYWRIGHT_BROWSERS_PATH", "PEERLOOM_CHROMIUM_EXECUTABLE"} {
		if value, ok := os.LookupEnv(name); ok {
			command.Env = append(command.Env, name+"="+value)
		}
	}
	command.Env = append(command.Env, "PEERLOOM_ADMIN_TEST_URL="+origin, "PEERLOOM_ADMIN_TEST_TENANT="+tenant)
	output, err := command.CombinedOutput()
	t.Logf("actual Chromium output:\n%s", strings.TrimSpace(string(output)))
	if err != nil {
		t.Fatal("actual Chromium console gate failed; inspect retained browser artifacts")
	}
	var applications, grants, audit, grantAudit, sessions int
	err = pool.QueryRow(ctx, browserEvidenceQuery, tenant, owner).Scan(&applications, &grants, &audit, &grantAudit, &sessions)
	if err != nil {
		t.Fatalf("browser database evidence query failed: %v", err)
	}
	if applications != 2 || grants != 2 || audit != 2 || grantAudit != 2 || sessions != 0 {
		t.Fatalf("browser database evidence mismatch: applications=%d grants=%d owner_audits=%d grant_audits=%d owner_sessions=%d", applications, grants, audit, grantAudit, sessions)
	}
}

const browserEvidenceQuery = `SELECT
(SELECT count(*) FROM applications WHERE tenant_id=$1),
(SELECT count(*) FROM registration_grants WHERE tenant_id=$1),
(SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND actor_type='admin_user' AND actor_id=$2::uuid::text AND action='application.create'),
(SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND actor_type='admin_user' AND actor_id=$2::uuid::text AND action='registration_grant.issue'),
(SELECT count(*) FROM admin_sessions WHERE tenant_id=$1 AND user_id=$2::uuid)`

func TestBrowserEvidenceParameterTypes(t *testing.T) {
	pool := testPool(t)
	var values [5]int
	err := pool.QueryRow(context.Background(), browserEvidenceQuery, "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002").Scan(&values[0], &values[1], &values[2], &values[3], &values[4])
	if err != nil {
		t.Fatalf("typed UUID/text evidence query failed: %v", err)
	}
	if values != [5]int{} {
		t.Fatalf("empty fixture has unexpected evidence: %v", values)
	}
}
