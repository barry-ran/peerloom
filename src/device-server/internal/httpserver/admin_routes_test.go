package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/barry-ran/peerloom/src/device-server/internal/httpapi"
)

func TestAdministrativeRoutesReachBoundApplication(t *testing.T) {
	paths := []struct{ method, path string }{
		{http.MethodGet, "/admin"},
		{http.MethodGet, "/admin/"},
		{http.MethodHead, "/admin/assets/style.css"},
		{http.MethodPost, "/admin/api/auth/login"},
		{http.MethodPost, "/admin/api/auth/logout"},
	}
	for _, item := range paths {
		t.Run(item.method+item.path, func(t *testing.T) {
			called := false
			application := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				if r.Method != item.method || r.URL.Path != item.path {
					t.Fatal("request mutated before application policy")
				}
				w.WriteHeader(http.StatusTeapot)
			})
			response := httptest.NewRecorder()
			New(nil, application).ServeHTTP(response, httptest.NewRequest(item.method, item.path, nil))
			if !called || response.Code != http.StatusTeapot {
				t.Fatalf("application not reached: called=%v status=%d", called, response.Code)
			}
		})
	}
}

func TestAdministrativePrefixDoesNotCaptureUnrelatedPaths(t *testing.T) {
	for _, path := range []string{"/administrator", "/admin-other", "/admins/"} {
		response := httptest.NewRecorder()
		New(nil, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("unrelated path delegated") })).ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("unexpected unrelated status: %d", response.Code)
		}
	}
	response := httptest.NewRecorder()
	New(nil).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/admin/", nil))
	if response.Code != http.StatusNotFound {
		t.Fatal("missing application must remain unavailable")
	}
}

func TestAdministrativeRoutesStayDisabledWithoutBoundAdminHandler(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("/", httpapi.New(nil))
	handler := New(nil, mux)
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
		for _, path := range []string{"/admin", "/admin/", "/admin/api/auth/login"} {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(method, path, nil))
			if response.Code != http.StatusNotFound {
				t.Fatalf("disabled %s %s status=%d", method, path, response.Code)
			}
		}
	}
}
