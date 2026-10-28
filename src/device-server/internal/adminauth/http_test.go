package adminauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPBoundaryRejectsBeforeAuthentication(t *testing.T) {
	h := &Handler{host: "admin.example", origin: "https://admin.example", cookie: "__Host-peerloom_admin", secure: true, slots: make(chan struct{}, 1)}
	for _, test := range []struct {
		name, path, host, origin, auth string
		status                         int
	}{
		{"wrong host", "/admin/api/auth/login", "other.example", "https://admin.example", "", 403},
		{"login csrf", "/admin/api/auth/login", "admin.example", "https://other.example", "", 403},
		{"service audience", "/admin/api/auth/login", "admin.example", "https://admin.example", "Bearer svc_test", 401},
		{"path encoding", "/admin/api/%61uth/login", "admin.example", "https://admin.example", "", 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "https://"+test.host+test.path, strings.NewReader("{}"))
			r.Host = test.host
			r.Header.Set("Origin", test.origin)
			if test.auth != "" {
				r.Header.Set("Authorization", test.auth)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != test.status {
				t.Fatalf("status=%d expected=%d", w.Code, test.status)
			}
		})
	}
	r := httptest.NewRequest("GET", "https://admin.example", nil)
	r.AddCookie(&http.Cookie{Name: h.cookie, Value: "one"})
	r.AddCookie(&http.Cookie{Name: h.cookie, Value: "two"})
	if _, ok := h.token(r); ok {
		t.Fatal("duplicate cookie accepted")
	}
	r = httptest.NewRequest("POST", "https://admin.example", nil)
	r.Header.Set("X-CSRF-Token", strings.Repeat("x", 43))
	if !csrfMatches(r, strings.Repeat("x", 43)) {
		t.Fatal("same csrf rejected")
	}
	r.Header.Add("X-CSRF-Token", strings.Repeat("x", 43))
	if csrfMatches(r, strings.Repeat("x", 43)) {
		t.Fatal("duplicate csrf accepted")
	}
}
