package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/identity"
)

type Service interface {
	Register(context.Context, identity.Registration, string) (identity.Credential, error)
	RegisterDirect(context.Context, identity.Registration, string, string) (identity.Credential, error)
	Authenticate(context.Context, string) (identity.Device, error)
	Refresh(context.Context, string, string) (identity.Credential, error)
}

type API struct {
	service Service
	slots   chan struct{}
}

func New(service Service) *API { return &API{service: service, slots: make(chan struct{}, 64)} }

func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := make([]byte, 16)
	if _, err := rand.Read(requestID); err != nil {
		http.Error(w, "request unavailable", 500)
		return
	}
	id := hex.EncodeToString(requestID)
	w.Header().Set("X-Request-ID", id)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	select {
	case a.slots <- struct{}{}:
		defer func() { <-a.slots }()
	default:
		writeError(w, id, identity.Fail("CONCURRENCY_LIMIT", 429))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	switch r.URL.Path {
	case "/v1/bootstrap":
		if !method(w, r, id, http.MethodGet) {
			return
		}
		respond(w, id, capabilities(), nil, http.StatusOK)
	case "/v1/device-registrations":
		if !method(w, r, id, http.MethodPost) {
			return
		}
		var input identity.Registration
		if err := decode(w, r, &input, false); err != nil {
			writeError(w, id, err)
			return
		}
		var result identity.Credential
		var err error
		if input.RegistrationGrant == "" {
			host, _, parseErr := net.SplitHostPort(r.RemoteAddr)
			if parseErr != nil {
				writeError(w, id, identity.Fail("INVALID_REMOTE_ADDRESS", 422))
				return
			}
			result, err = a.service.RegisterDirect(ctx, input, r.Header.Get("Idempotency-Key"), host)
		} else {
			result, err = a.service.Register(ctx, input, r.Header.Get("Idempotency-Key"))
		}
		respond(w, id, result, err, http.StatusCreated)
	case "/v1/device-self":
		if !method(w, r, id, http.MethodGet) {
			return
		}
		token, err := bearer(r)
		if err != nil {
			writeError(w, id, err)
			return
		}
		result, err := a.service.Authenticate(ctx, token)
		respond(w, id, result, err, http.StatusOK)
	case "/v1/device-credentials/refresh":
		if !method(w, r, id, http.MethodPost) {
			return
		}
		token, err := bearer(r)
		if err != nil {
			writeError(w, id, err)
			return
		}
		var input struct{}
		if err = decode(w, r, &input, true); err != nil {
			writeError(w, id, err)
			return
		}
		result, err := a.service.Refresh(ctx, token, r.Header.Get("Idempotency-Key"))
		respond(w, id, result, err, http.StatusOK)
	default:
		writeError(w, id, identity.Fail("NOT_FOUND", 404))
	}
}

func method(w http.ResponseWriter, r *http.Request, id, want string) bool {
	if r.Method == want {
		return true
	}
	w.Header().Set("Allow", want)
	writeError(w, id, identity.Fail("METHOD_NOT_ALLOWED", 405))
	return false
}

func decode(w http.ResponseWriter, r *http.Request, target any, allowEmpty bool) error {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return identity.Fail("CONTENT_TYPE_REQUIRED", 415)
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	err = decoder.Decode(target)
	if err != nil {
		if allowEmpty && errors.Is(err, io.EOF) {
			return nil
		}
		var max *http.MaxBytesError
		if errors.As(err, &max) {
			return identity.Fail("BODY_TOO_LARGE", 413)
		}
		return identity.Fail("INVALID_JSON", 422)
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		var max *http.MaxBytesError
		if errors.As(err, &max) {
			return identity.Fail("BODY_TOO_LARGE", 413)
		}
		return identity.Fail("INVALID_JSON", 422)
	}
	return nil
}

func bearer(r *http.Request) (string, error) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", identity.Fail("AUTH_INVALID", 401)
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || !strings.HasPrefix(parts[1], "dev_") {
		return "", identity.Fail("AUTH_INVALID", 401)
	}
	return parts[1], nil
}

func respond(w http.ResponseWriter, id string, result any, err error, status int) {
	if err != nil {
		writeError(w, id, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(result)
}
func writeError(w http.ResponseWriter, id string, err error) {
	status, code := 500, "INTERNAL_ERROR"
	var public *identity.Error
	if errors.As(err, &public) {
		status, code = public.Status, public.Code
	}
	if status == 401 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="device"`)
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "about:blank", "title": http.StatusText(status), "status": status, "code": code, "detail": code, "request_id": id})
}
