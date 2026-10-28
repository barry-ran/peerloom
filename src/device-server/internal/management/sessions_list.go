package management

import (
	"context"
	"fmt"
)

type SessionPage struct {
	Items      []Session `json:"items"`
	NextCursor string    `json:"next_cursor,omitempty"`
}

func (s *Service) ListSessions(ctx context.Context, p Principal, page Page) (SessionPage, error) {
	limit, cursor, err := parsePage(p, page, "sessions")
	if err != nil {
		return SessionPage{}, err
	}
	tx, err := s.begin(ctx, p, false)
	if err != nil {
		return SessionPage{}, err
	}
	defer rollback(tx)
	query := "SELECT " + sessionReadColumns + " FROM sessions WHERE tenant_id=$1"
	args := []any{p.tenantID}
	if cursor != nil {
		query += " AND (created_at,id)<($2,$3)"
		args = append(args, cursor.CreatedAt, cursor.ID)
	}
	args = append(args, limit+1)
	query += fmt.Sprintf(" ORDER BY created_at DESC,id DESC LIMIT $%d", len(args))
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return SessionPage{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	defer rows.Close()
	result := SessionPage{Items: make([]Session, 0, limit)}
	for rows.Next() {
		value, scanErr := scanSession(rows)
		if scanErr != nil {
			return SessionPage{}, fail("DATABASE_UNAVAILABLE", 503)
		}
		if len(result.Items) == limit {
			last := result.Items[len(result.Items)-1]
			result.NextCursor = encodeCursor(p, "sessions", last.CreatedAt, last.ID)
			break
		}
		result.Items = append(result.Items, value)
	}
	if err = rows.Err(); err != nil {
		return SessionPage{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	return result, nil
}
