package management

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/barry-ran/peerloom/src/device-server/internal/authorization"
)

func (h *Handler) notifySessions(sessions []authorization.Session) {
	if h.notify == nil {
		return
	}
	for _, session := range sessions {
		h.notify(session)
	}
}

func (h *Handler) serveResources(ctx context.Context, w http.ResponseWriter, r *http.Request, requestID string, p Principal) bool {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
	if !strings.HasPrefix(r.URL.Path, "/v1/") || len(parts) > 3 {
		return false
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		switch parts[0] {
		case "devices":
			page, filter, err := readDevicePage(r)
			if err != nil {
				writeError(w, requestID, err)
				return true
			}
			result, err := h.service.ListDevices(ctx, p, page, filter)
			respond(w, requestID, result, err, 200)
			return true
		case "connection-grants", "sessions", "audit-events":
			page, err := readPage(r)
			if err != nil {
				writeError(w, requestID, err)
				return true
			}
			switch parts[0] {
			case "connection-grants":
				result, err := h.service.ListConnectionGrants(ctx, p, page)
				respond(w, requestID, result, err, 200)
			case "sessions":
				result, err := h.service.ListSessions(ctx, p, page)
				respond(w, requestID, result, err, 200)
			case "audit-events":
				result, err := h.service.ListAudit(ctx, p, page)
				respond(w, requestID, result, err, 200)
			}
			return true
		}
	}
	if parts[0] == "connection-grants" && len(parts) == 1 {
		if r.Method != http.MethodPost {
			methodError(w, requestID, "POST")
			return true
		}
		var input ConnectionGrantInput
		if err := decode(w, r, &input); err != nil {
			writeError(w, requestID, err)
			return true
		}
		result, err := h.service.CreateConnectionGrant(ctx, p, input, r.Header.Get("Idempotency-Key"))
		respond(w, requestID, result, err, 201)
		return true
	}
	if len(parts) < 2 {
		return false
	}
	resource, id := parts[0], parts[1]
	if len(parts) == 3 {
		action := parts[2]
		if resource == "devices" && action == "revoke" {
			if r.Method != http.MethodPost {
				methodError(w, requestID, "POST")
				return true
			}
			result, err := h.service.RevokeDevice(ctx, p, id, r.Header.Get("Idempotency-Key"))
			if err == nil {
				h.notifySessions(result.Sessions)
			}
			respond(w, requestID, result, err, 200)
			return true
		}
		if resource == "sessions" && action == "terminate" {
			if r.Method != http.MethodPost {
				methodError(w, requestID, "POST")
				return true
			}
			result, err := h.service.TerminateSession(ctx, p, id, r.Header.Get("Idempotency-Key"))
			if err == nil {
				h.notifySessions([]authorization.Session{result})
			}
			respond(w, requestID, result, err, 200)
			return true
		}
		return false
	}
	switch resource {
	case "sessions":
		if r.Method != http.MethodGet {
			methodError(w, requestID, "GET")
			return true
		}
		result, err := h.service.GetSession(ctx, p, id)
		respond(w, requestID, result, err, 200)
		return true
	case "devices":
		switch r.Method {
		case http.MethodGet:
			result, err := h.service.GetDevice(ctx, p, id)
			respond(w, requestID, result, err, 200)
		case http.MethodPatch:
			var input DeviceUpdate
			if err := decode(w, r, &input); err != nil {
				writeError(w, requestID, err)
				return true
			}
			result, err := h.service.UpdateDevice(ctx, p, id, input, r.Header.Get("Idempotency-Key"))
			respond(w, requestID, result, err, 200)
		default:
			methodError(w, requestID, "GET, PATCH")
		}
		return true
	case "connection-grants":
		if r.Method == http.MethodDelete {
			result, err := h.service.RevokeConnectionGrant(ctx, p, id, r.Header.Get("Idempotency-Key"))
			if err == nil {
				h.notifySessions(result.Sessions)
			}
			respond(w, requestID, result, err, 200)
			return true
		}
		if r.Method != http.MethodGet {
			methodError(w, requestID, "GET, DELETE")
			return true
		}
		result, err := h.service.GetConnectionGrant(ctx, p, id)
		respond(w, requestID, result, err, 200)
		return true
	}
	return false
}

func readDevicePage(r *http.Request) (Page, DeviceFilter, error) {
	query := r.URL.Query()
	for key, values := range query {
		if (key != "limit" && key != "cursor" && key != "application_id" && key != "online" && key != "tags") || len(values) != 1 {
			return Page{}, DeviceFilter{}, fail("INVALID_QUERY", 422)
		}
	}
	page := Page{Cursor: query.Get("cursor")}
	if value := query.Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return Page{}, DeviceFilter{}, fail("INVALID_PAGE_LIMIT", 422)
		}
		page.Limit = parsed
	}
	filter := DeviceFilter{ApplicationID: query.Get("application_id")}
	if value, exists := query["tags"]; exists {
		if len(value[0]) > 8192 || json.Unmarshal([]byte(value[0]), &filter.Tags) != nil || filter.Tags == nil || !validProperties(filter.Tags) {
			return Page{}, DeviceFilter{}, fail("INVALID_TAG_FILTER", 422)
		}
	}
	if value, exists := query["online"]; exists {
		if value[0] != "true" && value[0] != "false" {
			return Page{}, DeviceFilter{}, fail("INVALID_QUERY", 422)
		}
		parsed := value[0] == "true"
		filter.Online = &parsed
	}
	return page, filter, nil
}
