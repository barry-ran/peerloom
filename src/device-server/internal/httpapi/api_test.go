package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/barry-ran/peerloom/src/device-server/internal/identity"
)

// Unit-only stub: persistence is exercised separately by tagged PostgreSQL tests.
type stubService struct {
	err      error
	calls    int
	directIP string
	device   identity.Device
}

func (s *stubService) Register(ctx context.Context, r identity.Registration, key string) (identity.Credential, error) {
	s.calls++
	if err := r.Validate(); err != nil {
		return identity.Credential{}, err
	}
	return identity.Credential{}, s.err
}
func (s *stubService) RegisterDirect(ctx context.Context, r identity.Registration, key, ip string) (identity.Credential, error) {
	s.directIP = ip
	return s.Register(ctx, r, key)
}
func (s *stubService) Authenticate(ctx context.Context, token string) (identity.Device, error) {
	s.calls++
	return s.device, s.err
}
func (s *stubService) Refresh(ctx context.Context, token, key string) (identity.Credential, error) {
	s.calls++
	return identity.Credential{}, s.err
}

func TestHTTPInputAndAudience(t *testing.T) {
	for _, tt := range []struct {
		name, path, method, body, auth string
		status                         int
	}{
		{"unknown", "/v1/unknown", "GET", "", "", 404},
		{"no-auth", "/v1/device-self", "GET", "", "", 401},
		{"wrong-audience", "/v1/device-self", "GET", "", "Bearer reg_secret", 401},
		{"method", "/v1/device-self", "POST", "{}", "", 405},
		{"unknown-field", "/v1/device-registrations", "POST", `{"tenant_id":"injected"}`, "", 422},
		{"trailing-json", "/v1/device-registrations", "POST", `{} {}`, "", 422},
		{"oversized", "/v1/device-registrations", "POST", `{"installation_public_key":"` + strings.Repeat("x", 17<<10) + `"}`, "", 413},
		{"invalid-shape", "/v1/device-registrations", "POST", `{}`, "", 422},
	} {
		t.Run(tt.name, func(t *testing.T) {
			api := New(&stubService{})
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			if tt.auth != "" {
				req.Header.Set("Authorization", tt.auth)
			}
			w := httptest.NewRecorder()
			api.ServeHTTP(w, req)
			if w.Code != tt.status {
				t.Fatalf("got status %d", w.Code)
			}
			var problem map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &problem); err != nil {
				t.Fatal(err)
			}
			if problem["request_id"] == "" || problem["request_id"] == nil {
				t.Fatal("missing request id")
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("sensitive response can be cached")
			}
		})
	}
}

func TestErrorSanitizationAndCapacity(t *testing.T) {
	api := New(&stubService{err: errors.New("postgres://user:secret@host")})
	req := httptest.NewRequest("GET", "/v1/device-self", nil)
	req.Header.Set("Authorization", "Bearer dev_example")
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)
	if w.Code != 500 || strings.Contains(w.Body.String(), "secret") {
		t.Fatal("internal error not sanitized")
	}
	for i := 0; i < cap(api.slots); i++ {
		api.slots <- struct{}{}
	}
	w = httptest.NewRecorder()
	api.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatal("capacity limit ignored")
	}
}

func TestDirectUsesTransportPeerNotForwardedHeaders(t *testing.T) {
	service := &stubService{}
	request := httptest.NewRequest("POST", "/v1/device-registrations", strings.NewReader(`{}`))
	request.RemoteAddr = "[2001:db8::42]:1234"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Forwarded-For", "192.0.2.99")
	request.Header.Set("Forwarded", "for=192.0.2.98")
	New(service).ServeHTTP(httptest.NewRecorder(), request)
	if service.directIP != "2001:db8::42" {
		t.Fatal("untrusted forwarding headers affected direct rate-limit identity")
	}
}

func TestDeviceSelfCredentialExpirySnapshotJSON(t *testing.T) {
	service := &stubService{device: identity.Device{
		ID:            "00000000-0000-4000-8000-000000000001",
		TenantID:      "00000000-0000-4000-8000-000000000002",
		ApplicationID: "00000000-0000-4000-8000-000000000003",
		Platform:      "linux", Metadata: json.RawMessage(`{}`),
		CredentialExpiresAt: "2026-10-29T12:00:00.123456Z",
	}}
	req := httptest.NewRequest("GET", "/v1/device-self", nil)
	req.Header.Set("Authorization", "Bearer dev_private-test-value")
	w := httptest.NewRecorder()
	New(service).ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("snapshot response not successful and private")
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body) != 6 {
		t.Fatal("unexpected public identity fields")
	}
	for _, field := range []string{"device_id", "tenant_id", "application_id", "platform", "metadata", "credential_expires_at"} {
		if _, ok := body[field]; !ok {
			t.Fatalf("missing public field %s", field)
		}
	}
	var expiry string
	if err := json.Unmarshal(body["credential_expires_at"], &expiry); err != nil || expiry != service.device.CredentialExpiresAt {
		t.Fatal("trusted expiry not preserved")
	}
	if strings.Contains(w.Body.String(), "private-test-value") {
		t.Fatal("credential leaked in snapshot")
	}
}
