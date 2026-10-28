package management

import (
	"context"
	"net/http"
	"strings"
)

func (h *Handler) serveWebhooks(ctx context.Context, w http.ResponseWriter, r *http.Request, id string, p Principal) bool {
	if r.URL.Path == "/v1/webhook-endpoints" {
		switch r.Method {
		case http.MethodGet:
			if len(r.URL.Query()) != 0 {
				writeError(w, id, fail("INVALID_QUERY", 422))
				return true
			}
			result, err := h.service.ListWebhooks(ctx, p)
			respond(w, id, result, err, 200)
		case http.MethodPost:
			var input WebhookInput
			if err := decode(w, r, &input); err != nil {
				writeError(w, id, err)
				return true
			}
			result, err := h.service.CreateWebhook(ctx, p, input, r.Header.Get("Idempotency-Key"))
			respond(w, id, result, err, 201)
		default:
			methodError(w, id, "GET, POST")
		}
		return true
	}
	if !strings.HasPrefix(r.URL.Path, "/v1/webhook-endpoints/") {
		return false
	}
	target := strings.TrimPrefix(r.URL.Path, "/v1/webhook-endpoints/")
	switch r.Method {
	case http.MethodPatch:
		var input WebhookUpdate
		if err := decode(w, r, &input); err != nil {
			writeError(w, id, err)
			return true
		}
		result, err := h.service.UpdateWebhook(ctx, p, target, input, r.Header.Get("Idempotency-Key"))
		respond(w, id, result, err, 200)
	case http.MethodDelete:
		enabled := false
		result, err := h.service.UpdateWebhook(ctx, p, target, WebhookUpdate{Enabled: &enabled}, r.Header.Get("Idempotency-Key"))
		respond(w, id, result, err, 200)
	default:
		methodError(w, id, "PATCH, DELETE")
	}
	return true
}
