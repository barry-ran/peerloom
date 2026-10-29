package relay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/authorization"
	"github.com/barry-ran/peerloom/src/device-server/internal/identity"
)

type Authenticator interface {
	Authenticate(context.Context, string) (identity.Device, error)
}
type Handler struct {
	service *Service
	auth    Authenticator
	slots   chan struct{}
}

func NewHandler(service *Service, auth Authenticator) *Handler {
	return &Handler{service: service, auth: auth, slots: make(chan struct{}, 64)}
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		http.Error(w, "request unavailable", 503)
		return
	}
	requestID := hex.EncodeToString(random[:])
	w.Header().Set("X-Request-ID", requestID)
	sendError := func(err error) {
		code, status := "RELAY_UNAVAILABLE", 503
		var domain *Error
		var auth *identity.Error
		if errors.As(err, &domain) {
			code, status = domain.Code, domain.Status
		} else if errors.As(err, &auth) {
			code, status = auth.Code, auth.Status
		}
		if status == 401 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="device"`)
		}
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "about:blank", "title": http.StatusText(status), "status": status, "code": code, "detail": code, "request_id": requestID})
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		sendError(failure("CONCURRENCY_LIMIT", 429))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	headers := r.Header.Values("Authorization")
	if len(headers) != 1 {
		sendError(failure("AUTH_INVALID", 401))
		return
	}
	parts := strings.Fields(headers[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		sendError(failure("AUTH_INVALID", 401))
		return
	}
	actor, err := h.auth.Authenticate(ctx, parts[1])
	if err != nil {
		sendError(err)
		return
	}
	path := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/device-sessions/"), "/")
	if !strings.HasPrefix(r.URL.Path, "/v1/device-sessions/") || len(path) != 2 || path[1] != "ice-servers" || !uuidPattern.MatchString(path[0]) {
		sendError(failure("NOT_FOUND", 404))
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		sendError(failure("METHOD_NOT_ALLOWED", 405))
		return
	}
	if r.URL.RawQuery != "" || r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
		sendError(failure("INVALID_INPUT", 422))
		return
	}
	epochs := r.Header.Values("X-Peerloom-Target-Epoch")
	if len(epochs) > 1 {
		sendError(failure("INVALID_INPUT", 422))
		return
	}
	ctx = authorization.WithExclusiveAuthority(ctx, r.Header.Get("X-Peerloom-Target-Epoch"), "")
	result, err := h.service.IssueAuthenticated(ctx, actor, path[0], parts[1])
	if err != nil {
		sendError(err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(result)
}
