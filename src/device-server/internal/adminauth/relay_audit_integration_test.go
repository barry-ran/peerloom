//go:build integration

package adminauth

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/management"
	"github.com/barry-ran/peerloom/src/device-server/internal/relay"
)

func TestBrowserRelayAuditActorAndIsolation(t *testing.T) {
	pool, auth, tenant, user := offlineFixture(t)
	ctx := context.Background()
	issuer, err := relay.New(map[string]relay.SecretBinding{"fixture": {TenantID: tenant, Secret: []byte(strings.Repeat("s", 32)), URLs: []string{"turn:relay.example.com:3478?transport=udp"}}}, 5*time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := management.NewWithRelay(pool, []byte(strings.Repeat("k", 32)), management.DefaultSettings(), nil, issuer)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.WithBrowserAuthority(auth)
	if err != nil {
		t.Fatal(err)
	}
	handler := management.NewHandler(backend)
	owner, err := auth.Login(ctx, tenant, "owner", offlinePassword, "fixture-ip")
	if err != nil {
		t.Fatal(err)
	}
	service, err := management.IssueKey(ctx, pool, tenant, management.ScopeAdmin, time.Hour, "audit fixture")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := backend.Authenticate(ctx, service.ServiceCredential)
	if err != nil {
		t.Fatal(err)
	}
	invoke := func(method, path, body, key, token string, browser bool, want int) management.RelayNode {
		t.Helper()
		request := httptest.NewRequest(method, "http://fixture"+path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", key)
		response := httptest.NewRecorder()
		if browser {
			handler.ServeBrowserHTTP(response, request, token)
		} else {
			request.Header.Set("Authorization", "Bearer "+token)
			handler.ServeHTTP(response, request)
		}
		if response.Code != want {
			t.Fatalf("%s relay status=%d want=%d", method, response.Code, want)
		}
		var node management.RelayNode
		if want < 300 {
			if err := json.Unmarshal(response.Body.Bytes(), &node); err != nil {
				t.Fatal("invalid relay JSON")
			}
		}
		return node
	}
	body := `{"name":"audit fixture","endpoint":"turn:relay.example.com:3478?transport=udp","secret_ref":"fixture"}`
	for _, tc := range []struct {
		token, actorType, actorID string
		browser                   bool
	}{
		{owner.Token, "admin_user", user, true},
		{service.ServiceCredential, "service_credential", principal.CredentialID(), false},
	} {
		node := invoke("POST", "/v1/relay-nodes", body, "audit-create", tc.token, tc.browser, 201)
		replay := invoke("POST", "/v1/relay-nodes", body, "audit-create", tc.token, tc.browser, 201)
		if replay.ID != node.ID {
			t.Fatal("relay replay changed identity")
		}
		invoke("PATCH", "/v1/relay-nodes/"+node.ID, `{"name":"updated"}`, "audit-update", tc.token, tc.browser, 200)
		var count, mismatched int
		if err := pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE actor_type<>$2 OR actor_id IS DISTINCT FROM $3) FROM audit_events WHERE resource_id=$1 AND resource_type='relay_node'`, node.ID, tc.actorType, tc.actorID).Scan(&count, &mismatched); err != nil {
			t.Fatal(err)
		}
		if count != 2 || mismatched != 0 {
			t.Fatalf("relay audit count=%d mismatched=%d for %s", count, mismatched, tc.actorType)
		}
		if tc.browser {
			if _, err := CreateUser(ctx, pool, tenant, "reader", offlinePassword, management.ScopeRead); err != nil {
				t.Fatal(err)
			}
			reader, err := auth.Login(ctx, tenant, "reader", offlinePassword, "fixture-reader")
			if err != nil {
				t.Fatal(err)
			}
			invoke("PATCH", "/v1/relay-nodes/"+node.ID, `{"enabled":false}`, "reader-denied", reader.Token, true, 403)
			var foreign string
			if err := pool.QueryRow(ctx, `INSERT INTO tenants(name) VALUES('foreign audit fixture') RETURNING id::text`).Scan(&foreign); err != nil {
				t.Fatal(err)
			}
			if _, err := CreateUser(ctx, pool, foreign, "owner", offlinePassword, management.ScopeAdmin); err != nil {
				t.Fatal(err)
			}
			other, err := auth.Login(ctx, foreign, "owner", offlinePassword, "fixture-foreign")
			if err != nil {
				t.Fatal(err)
			}
			invoke("PATCH", "/v1/relay-nodes/"+node.ID, `{"enabled":false}`, "foreign-denied", other.Token, true, 404)
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE resource_id=$1 AND resource_type='relay_node'`, node.ID).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 2 {
				t.Fatal("denied mutation appended successful relay audit")
			}
		}
	}
}
