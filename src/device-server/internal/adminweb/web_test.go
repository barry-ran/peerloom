package adminweb

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuiltAssetsAndSecurityHeaders(t *testing.T) {
	handler := Handler()
	for _, path := range []string{"/admin/", "/admin/assets/app.js", "/admin/assets/style.css"} {
		t.Run(path, func(t *testing.T) {
			get := httptest.NewRecorder()
			handler.ServeHTTP(get, httptest.NewRequest(http.MethodGet, path, nil))
			if get.Code != http.StatusOK || get.Body.Len() == 0 {
				t.Fatal("required built asset missing")
			}
			if get.Header().Get("Cache-Control") != "no-store" || get.Header().Get("X-Content-Type-Options") != "nosniff" || get.Header().Get("Referrer-Policy") != "no-referrer" {
				t.Fatal("security headers missing")
			}
			csp := get.Header().Get("Content-Security-Policy")
			if !strings.Contains(csp, "frame-ancestors 'none'") || !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
				t.Fatal("CSP weakened")
			}
			head := httptest.NewRecorder()
			handler.ServeHTTP(head, httptest.NewRequest(http.MethodHead, path, nil))
			if head.Code != http.StatusOK || head.Body.Len() != 0 || head.Header().Get("Content-Type") != get.Header().Get("Content-Type") {
				t.Fatal("HEAD asset contract mismatch")
			}
		})
	}
}

func TestOnlyExplicitPublicAssetsAndMethods(t *testing.T) {
	for _, path := range []string{"/admin/assets/../secret", "/admin/assets/%61pp.js", "/admin/assets/app.js.map", "/admin/assets/credentials.json", "/admin/unknown"} {
		w := httptest.NewRecorder()
		Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusNotFound {
			t.Fatalf("unexpected asset exposed: %s", path)
		}
	}
	w := httptest.NewRecorder()
	Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/admin/", nil))
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD" {
		t.Fatal("mutating method accepted by static handler")
	}
}
