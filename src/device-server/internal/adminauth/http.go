package adminauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/management"
)

type HTTPConfig struct {
	Origin              string
	DevelopmentLoopback bool
}
type Handler struct {
	service              *Service
	management           *management.Handler
	origin, host, cookie string
	secure               bool
	slots                chan struct{}
}

func NewHandler(service *Service, backend *management.Handler, config HTTPConfig) (*Handler, error) {
	if service == nil || backend == nil {
		return nil, errors.New("admin services required")
	}
	u, err := url.Parse(config.Origin)
	if err != nil || u.User != nil || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("canonical admin origin required")
	}
	secure := u.Scheme == "https"
	if !secure {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || !config.DevelopmentLoopback || ip == nil || !ip.IsLoopback() {
			return nil, errors.New("HTTPS required except explicit IP-literal loopback development")
		}
	}
	name := "__Host-peerloom_admin"
	if !secure {
		name = "peerloom_admin_dev"
	}
	return &Handler{service: service, management: backend, origin: u.Scheme + "://" + u.Host, host: u.Host, cookie: name, secure: secure, slots: make(chan struct{}, 64)}, nil
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := make([]byte, 16)
	if _, err := rand.Read(requestID); err != nil {
		http.Error(w, "request unavailable", 500)
		return
	}
	w.Header().Set("X-Request-ID", hex.EncodeToString(requestID))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.Host != h.host {
		h.failure(w, problem("ORIGIN_REQUIRED", 403))
		return
	}
	if len(r.Header.Values("Authorization")) != 0 {
		h.failure(w, problem("ADMIN_AUTH_INVALID", 401))
		return
	}
	if strings.Contains(r.URL.EscapedPath(), "%") {
		h.failure(w, problem("INVALID_PATH", 400))
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		h.failure(w, problem("ADMIN_BUSY", 429))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	if r.URL.Path == "/admin/api/auth/login" {
		if r.Method != http.MethodPost {
			h.method(w, "POST")
			return
		}
		if !h.sameOrigin(r) {
			h.failure(w, problem("ORIGIN_REQUIRED", 403))
			return
		}
		var input struct {
			TenantID string `json:"tenant_id"`
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if !decodeJSON(w, r, &input) {
			h.failure(w, problem("INVALID_INPUT", 422))
			return
		}
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || net.ParseIP(ip) == nil {
			h.failure(w, problem("INVALID_REMOTE", 400))
			return
		}
		result, err := h.service.Login(ctx, input.TenantID, input.Username, input.Password, ip)
		if err != nil {
			h.failure(w, err)
			return
		}
		// Never serialize LoginResult: only the HttpOnly cookie receives its token.
		http.SetCookie(w, &http.Cookie{Name: h.cookie, Value: result.Token, Path: "/", HttpOnly: true, Secure: h.secure, SameSite: http.SameSiteStrictMode, MaxAge: int(SessionTTL / time.Second), Expires: result.Session.ExpiresAt})
		h.json(w, result.Session)
		return
	}
	token, ok := h.token(r)
	if !ok {
		h.failure(w, problem("ADMIN_AUTH_INVALID", 401))
		return
	}
	session, err := h.service.Session(ctx, token)
	if err != nil {
		h.failure(w, err)
		return
	}
	if r.URL.Path == "/admin/api/auth/session" {
		if r.Method != http.MethodGet {
			h.method(w, "GET")
			return
		}
		h.json(w, session)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if !h.sameOrigin(r) || !csrfMatches(r, session.CSRFToken) {
			h.failure(w, problem("CSRF_REQUIRED", 403))
			return
		}
	}
	if r.URL.Path == "/admin/api/auth/logout" {
		if r.Method != http.MethodPost {
			h.method(w, "POST")
			return
		}
		if err = h.service.Logout(ctx, token); err != nil {
			h.failure(w, err)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: h.cookie, Value: "", Path: "/", HttpOnly: true, Secure: h.secure, SameSite: http.SameSiteStrictMode, MaxAge: -1, Expires: time.Unix(1, 0)})
		h.json(w, map[string]string{"status": "logged_out"})
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/admin/api/v1/") {
		h.failure(w, problem("NOT_FOUND", 404))
		return
	}
	forwarded := r.Clone(ctx)
	destination := *r.URL
	destination.Path = strings.TrimPrefix(r.URL.Path, "/admin/api")
	destination.RawPath = ""
	forwarded.URL = &destination
	h.management.ServeBrowserHTTP(w, forwarded, token)
}
func (h *Handler) sameOrigin(r *http.Request) bool {
	origins := r.Header.Values("Origin")
	return len(origins) == 1 && origins[0] == h.origin
}
func csrfMatches(r *http.Request, expected string) bool {
	values := r.Header.Values("X-CSRF-Token")
	return len(values) == 1 && len(values[0]) == 43 && subtle.ConstantTimeCompare([]byte(values[0]), []byte(expected)) == 1
}
func (h *Handler) token(r *http.Request) (string, bool) {
	var result string
	count := 0
	for _, cookie := range r.Cookies() {
		if cookie.Name == h.cookie {
			result = cookie.Value
			count++
		}
	}
	return result, count == 1
}
func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return false
	}
	return errors.Is(decoder.Decode(&struct{}{}), io.EOF)
}
func (h *Handler) json(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(value)
}
func (h *Handler) failure(w http.ResponseWriter, err error) {
	status, code := 500, "INTERNAL_ERROR"
	var public *management.Error
	if errors.As(err, &public) {
		status, code = public.Status, public.Code
	}
	if status == 429 {
		w.Header().Set("Retry-After", "60")
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "about:blank", "status": status, "code": code, "title": http.StatusText(status), "request_id": w.Header().Get("X-Request-ID")})
}
func (h *Handler) method(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	h.failure(w, problem("METHOD_NOT_ALLOWED", 405))
}
