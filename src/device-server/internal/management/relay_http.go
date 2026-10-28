package management

import (
	"context"
	"net/http"
	"strings"
)

func (h *Handler) serveRelays(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, p Principal) bool {
	if r.URL.Path == "/v1/relay-nodes" {
		switch r.Method {
		case http.MethodGet:
			page, err := readPage(r)
			if err != nil {
				writeError(w, requestID, err)
				return true
			}
			result, err := h.service.ListRelayNodes(ctx, p, page)
			respond(w, requestID, result, err, 200)
		case http.MethodPost:
			var input RelayNodeInput
			if err := decode(w, r, &input); err != nil {
				writeError(w, requestID, err)
				return true
			}
			result, err := h.service.CreateRelayNode(ctx, p, input, r.Header.Get("Idempotency-Key"))
			respond(w, requestID, result, err, 201)
		default:
			methodError(w, requestID, "GET, POST")
		}
		return true
	}
	if !strings.HasPrefix(r.URL.Path, "/v1/relay-nodes/") {
		return false
	}
	id := strings.TrimPrefix(r.URL.Path, "/v1/relay-nodes/")
	switch r.Method {
	case http.MethodGet:
		result, err := h.service.GetRelayNode(ctx, p, id)
		respond(w, requestID, result, err, 200)
	case http.MethodPatch:
		var input RelayNodeUpdate
		if err := decode(w, r, &input); err != nil {
			writeError(w, requestID, err)
			return true
		}
		result, err := h.service.UpdateRelayNode(ctx, p, id, input, r.Header.Get("Idempotency-Key"))
		respond(w, requestID, result, err, 200)
	case http.MethodDelete:
		enabled := false
		result, err := h.service.UpdateRelayNode(ctx, p, id, RelayNodeUpdate{Enabled: &enabled}, r.Header.Get("Idempotency-Key"))
		respond(w, requestID, result, err, 200)
	default:
		methodError(w, requestID, "GET, PATCH, DELETE")
	}
	return true
}
