package management

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/barry-ran/peerloom/src/device-server/internal/authorization"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Handler struct {
	service *Service
	slots   chan struct{}
	notify  func(authorization.Session)
}

func NewHandler(service *Service, notify ...func(authorization.Session)) *Handler {
	h := &Handler{service: service, slots: make(chan struct{}, 64)}
	if len(notify) > 0 {
		h.notify = notify[0]
	}
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.serve(w, r, func(ctx context.Context) (Principal, error) {
		values := r.Header.Values("Authorization")
		if len(values) != 1 {
			return Principal{}, fail("SERVICE_AUTH_INVALID", 401)
		}
		parts := strings.Fields(values[0])
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			return Principal{}, fail("SERVICE_AUTH_INVALID", 401)
		}
		return h.service.Authenticate(ctx, parts[1])
	})
}

// ServeBrowserHTTP is called only behind the admin session/Origin/CSRF boundary.
// It does not accept service credentials or infer browser authority from a body.
func (h *Handler) ServeBrowserHTTP(w http.ResponseWriter, r *http.Request, token string) {
	h.serve(w, r, func(ctx context.Context) (Principal, error) { return h.service.authenticateBrowser(ctx, token) })
}
func (h *Handler) serve(w http.ResponseWriter, r *http.Request, authenticate func(context.Context) (Principal, error)) {
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
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		writeError(w, id, fail("CONCURRENCY_LIMIT", 429))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	p, err := authenticate(ctx)
	if err != nil {
		writeError(w, id, err)
		return
	}

	if h.serveWebhooks(ctx, w, r, id, p) || h.serveRelays(ctx, w, r, id, p) || h.serveResources(ctx, w, r, id, p) {
		return
	}
	switch {
	case r.URL.Path == "/v1/applications":
		switch r.Method {
		case http.MethodPost:
			var input ApplicationInput
			if err = decode(w, r, &input); err != nil {
				writeError(w, id, err)
				return
			}
			result, err := h.service.CreateApplication(ctx, p, input, r.Header.Get("Idempotency-Key"))
			respond(w, id, result, err, 201)
		case http.MethodGet:
			page, err := readPage(r)
			if err != nil {
				writeError(w, id, err)
				return
			}
			result, err := h.service.ListApplications(ctx, p, page)
			respond(w, id, result, err, 200)
		default:
			methodError(w, id, "GET, POST")
		}
	case strings.HasPrefix(r.URL.Path, "/v1/applications/"):
		if r.Method == http.MethodPatch {
			var input ApplicationUpdate
			if err = decode(w, r, &input); err != nil {
				writeError(w, id, err)
				return
			}
			result, err := h.service.UpdateApplication(ctx, p, strings.TrimPrefix(r.URL.Path, "/v1/applications/"), input, r.Header.Get("Idempotency-Key"))
			if err == nil {
				h.notifySessions(result.Sessions)
			}
			respond(w, id, result, err, 200)
			return
		}
		if r.Method != http.MethodGet {
			methodError(w, id, "GET, PATCH")
			return
		}
		result, err := h.service.GetApplication(ctx, p, strings.TrimPrefix(r.URL.Path, "/v1/applications/"))
		respond(w, id, result, err, 200)
	case r.URL.Path == "/v1/registration-grants":
		if r.Method != http.MethodPost {
			methodError(w, id, "POST")
			return
		}
		var input RegistrationGrantInput
		if err = decode(w, r, &input); err != nil {
			writeError(w, id, err)
			return
		}
		result, err := h.service.IssueRegistrationGrant(ctx, p, input, r.Header.Get("Idempotency-Key"))
		respond(w, id, result, err, 201)
	default:
		writeError(w, id, fail("NOT_FOUND", 404))
	}
}

func readPage(r *http.Request) (Page, error) {
	for key, values := range r.URL.Query() {
		if (key != "limit" && key != "cursor") || len(values) != 1 {
			return Page{}, fail("INVALID_QUERY", 422)
		}
	}
	page := Page{Cursor: r.URL.Query().Get("cursor")}
	if value := r.URL.Query().Get("limit"); value != "" {
		limit, err := strconv.Atoi(value)
		if err != nil {
			return Page{}, fail("INVALID_PAGE_LIMIT", 422)
		}
		page.Limit = limit
	}
	return page, nil
}

func decode(w http.ResponseWriter, r *http.Request, target any) error {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return fail("CONTENT_TYPE_REQUIRED", 415)
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(target); err != nil {
		var maximum *http.MaxBytesError
		if errors.As(err, &maximum) {
			return fail("BODY_TOO_LARGE", 413)
		}
		return fail("INVALID_JSON", 422)
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fail("INVALID_JSON", 422)
	}
	return nil
}

func methodError(w http.ResponseWriter, id, allowed string) {
	w.Header().Set("Allow", allowed)
	writeError(w, id, fail("METHOD_NOT_ALLOWED", 405))
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
	var public *Error
	if errors.As(err, &public) {
		status, code = public.Status, public.Code
	}
	if status == 401 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="tenant-service"`)
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "about:blank", "title": http.StatusText(status), "status": status, "code": code, "detail": code, "request_id": id})
}
