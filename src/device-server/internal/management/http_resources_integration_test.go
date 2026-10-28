//go:build integration

package management

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/barry-ran/peerloom/src/device-server/internal/authorization"
)

func TestHTTPPartialPatchAndPostCommitNotification(t *testing.T) {
	f := setup(t)
	pair := makePair(t, f)
	notifications := 0
	handler := NewHandler(f.service, func(value authorization.Session) {
		var state string
		if err := f.pool.QueryRow(f.ctx, "SELECT state FROM sessions WHERE id=$1", value.ID).Scan(&state); err != nil || state != "closed" {
			t.Errorf("notification preceded commit: %s %v", state, err)
		}
		notifications++
	})
	call := func(method, path, key, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer "+f.credential.ServiceCredential)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	path := "/v1/devices/" + pair.actors[0].ID
	response := call("PATCH", path, "patch-device-limit", `{"max_connections":0}`)
	if response.Code != 200 {
		t.Fatalf("patch limit status=%d body=%s", response.Code, response.Body.String())
	}
	var device Device
	if err := json.Unmarshal(response.Body.Bytes(), &device); err != nil || !device.Connectable || device.MaxConnections == nil || *device.MaxConnections != 0 {
		t.Fatalf("patch changed omitted field: %+v %v", device, err)
	}
	response = call("PATCH", path, "patch-device-inherit", `{"max_connections":null,"connectable":false}`)
	if response.Code != 200 {
		t.Fatalf("patch inherit status=%d", response.Code)
	}
	if err := json.Unmarshal(response.Body.Bytes(), &device); err != nil || device.Connectable || device.MaxConnections != nil {
		t.Fatalf("null inheritance / false lost: %+v %v", device, err)
	}
	if response = call("PATCH", path, "empty-device-patch", `{}`); response.Code != 422 {
		t.Fatalf("empty patch accepted: %d", response.Code)
	}
	if response = call("PATCH", path, "tenant-device-patch", `{"tenant_id":"spoof"}`); response.Code != 422 {
		t.Fatalf("unknown property accepted: %d", response.Code)
	}
	response = call("PATCH", "/v1/applications/"+pair.actors[0].ApplicationID, "patch-only-name", `{"name":"重命名"}`)
	if response.Code != 200 {
		t.Fatalf("application patch status=%d", response.Code)
	}
	var change ApplicationChange
	if err := json.Unmarshal(response.Body.Bytes(), &change); err != nil || !change.Application.Enabled || change.Application.MaxConnections != 8 {
		t.Fatalf("application patch replaced omitted defaults: %+v %v", change, err)
	}
	session, err := pair.auth.Request(f.ctx, pair.actors[0], pair.actors[1].ID, "00000000-0000-0000-0000-000000000007")
	if err != nil {
		t.Fatal(err)
	}
	response = call("POST", "/v1/sessions/"+session.ID+"/terminate", "http-terminate-session", "")
	if response.Code != 200 || notifications != 1 {
		t.Fatalf("termination/notification status=%d events=%d", response.Code, notifications)
	}
	response = call("DELETE", "/v1/connection-grants/"+pair.grant.ID, "http-revoke-grant", "")
	if response.Code != 200 {
		t.Fatalf("contract DELETE grant: %d", response.Code)
	}
	response = call("PATCH", path, "patch-filter-tags", `{"tags":{"role":"sensor"}}`)
	if response.Code != 200 {
		t.Fatalf("patch tags: %d", response.Code)
	}
	filtered, err := f.service.ListDevices(f.ctx, f.principal, Page{}, DeviceFilter{Tags: map[string]any{"role": "sensor"}})
	if err != nil || len(filtered.Items) != 1 || filtered.Items[0].ID != pair.actors[0].ID {
		t.Fatalf("tag filter: %+v %v", filtered, err)
	}
	for _, route := range []string{"devices", "sessions", "connection-grants", "audit-events"} {
		if response = call("GET", "/v1/"+route+"?limit=1", "", ""); response.Code != 200 {
			t.Fatalf("list %s status=%d", route, response.Code)
		}
	}
}
