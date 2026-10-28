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
	return identity.Device{}, s.err
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
