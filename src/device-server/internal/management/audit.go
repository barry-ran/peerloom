package management

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"
)

type AuditEvent struct {
	ID           string          `json:"id"`
	ActorType    string          `json:"actor_type"`
	ActorID      *string         `json:"actor_id"`
	Action       string          `json:"action"`
	ResourceType *string         `json:"resource_type"`
	ResourceID   *string         `json:"resource_id"`
	Details      json.RawMessage `json:"details"`
	CreatedAt    time.Time       `json:"created_at"`
}

type AuditPage struct {
	Items      []AuditEvent `json:"items"`
	NextCursor string       `json:"next_cursor,omitempty"`
}

func (s *Service) ListAudit(ctx context.Context, p Principal, page Page) (AuditPage, error) {
	limit := page.Limit
	if limit == 0 {
		limit = 50
	}
	if limit < 1 || limit > 100 {
		return AuditPage{}, fail("INVALID_PAGE_LIMIT", 422)
	}
	var before int64
	if page.Cursor != "" {
		if len(page.Cursor) > 1024 {
			return AuditPage{}, fail("INVALID_CURSOR", 422)
		}
		data, err := base64.RawURLEncoding.DecodeString(page.Cursor)
		if err != nil {
			return AuditPage{}, fail("INVALID_CURSOR", 422)
		}
		var cursor pageCursor
		decoder := json.NewDecoder(strings.NewReader(string(data)))
		decoder.DisallowUnknownFields()
		if err = decoder.Decode(&cursor); err != nil || cursor.Version != 1 || cursor.Tenant != p.tenantID || cursor.Resource != "audit" {
			return AuditPage{}, fail("INVALID_CURSOR", 422)
		}
		if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return AuditPage{}, fail("INVALID_CURSOR", 422)
		}
		before, err = strconv.ParseInt(cursor.ID, 10, 64)
		if err != nil || before < 1 {
			return AuditPage{}, fail("INVALID_CURSOR", 422)
		}
	}
	tx, err := s.begin(ctx, p, false)
	if err != nil {
		return AuditPage{}, err
	}
	defer rollback(tx)
	rows, err := tx.Query(ctx, `SELECT id,actor_type,actor_id,action,resource_type,resource_id,details,created_at
FROM audit_events WHERE tenant_id=$1 AND ($2::bigint=0 OR id<$2) ORDER BY id DESC LIMIT $3`, p.tenantID, before, limit+1)
	if err != nil {
		return AuditPage{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	defer rows.Close()
	result := AuditPage{Items: make([]AuditEvent, 0, limit)}
	for rows.Next() {
		var value AuditEvent
		var id int64
		if err = rows.Scan(&id, &value.ActorType, &value.ActorID, &value.Action, &value.ResourceType, &value.ResourceID, &value.Details, &value.CreatedAt); err != nil {
			return AuditPage{}, fail("DATABASE_UNAVAILABLE", 503)
		}
		value.ID = strconv.FormatInt(id, 10)
		if len(result.Items) == limit {
			last := result.Items[len(result.Items)-1]
			result.NextCursor = encodeCursor(p, "audit", last.CreatedAt, last.ID)
			break
		}
		result.Items = append(result.Items, value)
	}
	if err = rows.Err(); err != nil {
		return AuditPage{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	return result, nil
}
