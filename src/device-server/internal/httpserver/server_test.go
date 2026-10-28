package httpserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEndpoints(t *testing.T) {
	for _, tt := range []struct {
		path   string
		method string
		fail   bool
		stop   bool
		status int
	}{
		{"/healthz", "GET", true, false, 200}, {"/readyz", "GET", false, false, 200},
		{"/readyz", "GET", true, false, 503}, {"/readyz", "GET", false, true, 503},
		{"/missing", "GET", false, false, 404}, {"/healthz", "POST", false, false, 405},
		{"/metrics", "GET", false, false, 200},
	} {
		t.Run(tt.path+tt.method+http.StatusText(tt.status), func(t *testing.T) {
			h := New(func(ctx context.Context) error {
				if _, ok := ctx.Deadline(); !ok {
					t.Error("no readiness deadline")
				}
				if tt.fail {
					return errors.New("secret database details")
				}
				return nil
			})
			if tt.stop {
				h.Stop()
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(tt.method, tt.path, nil))
			if w.Code != tt.status {
				t.Fatalf("got %d", w.Code)
			}
			if strings.Contains(w.Body.String(), "secret") {
				t.Fatal("internal error leaked")
			}
		})
	}
}
