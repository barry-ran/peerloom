package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// Handler only reports this process and its configured dependency readiness.
// It does not claim that the relay or all SDK platforms are ready.
type Handler struct {
	check    func(context.Context) error
	stopping atomic.Bool
	requests atomic.Uint64
	api      http.Handler
}

func New(check func(context.Context) error, api ...http.Handler) *Handler {
	h := &Handler{check: check}
	if len(api) > 0 {
		h.api = api[0]
	}
	return h
}
func (h *Handler) Stop() { h.stopping.Store(true) }

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.requests.Add(1)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if h.api != nil && (strings.HasPrefix(r.URL.Path, "/v1/") || r.URL.Path == "/admin" || strings.HasPrefix(r.URL.Path, "/admin/")) {
		// The bound application owns API and administrator route authentication.
		// Shutdown stops accepting connections; existing requests may drain.
		h.api.ServeHTTP(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		problem(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	switch r.URL.Path {
	case "/healthz":
		writeJSON(w, http.StatusOK, map[string]string{"status": "alive"})
	case "/readyz":
		if h.stopping.Load() {
			problem(w, http.StatusServiceUnavailable, "NOT_READY")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if h.check == nil || h.check(ctx) != nil {
			problem(w, http.StatusServiceUnavailable, "NOT_READY")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready", "scope": "control_plane_dependencies"})
	case "/metrics":
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprintf(w, "# HELP peerloom_http_requests_total HTTP requests handled by this process.\n# TYPE peerloom_http_requests_total counter\npeerloom_http_requests_total %d\n", h.requests.Load())
	default:
		problem(w, http.StatusNotFound, "NOT_FOUND")
	}
}

func problem(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "about:blank", "title": http.StatusText(status), "status": status, "code": code})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
