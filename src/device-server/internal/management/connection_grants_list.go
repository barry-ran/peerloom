package management

import (
	"context"
	"fmt"
)

type ConnectionGrantPage struct {
	Items      []ConnectionGrant `json:"items"`
	NextCursor string            `json:"next_cursor,omitempty"`
}

func (s *Service) ListConnectionGrants(ctx context.Context, p Principal, page Page) (ConnectionGrantPage, error) {
	limit, cursor, err := parsePage(p, page, "connection_grants")
	if err != nil {
		return ConnectionGrantPage{}, err
	}
	tx, err := s.begin(ctx, p, false)
	if err != nil {
		return ConnectionGrantPage{}, err
	}
	defer rollback(tx)
	query := "SELECT " + grantColumns + " FROM connection_grants WHERE tenant_id=$1"
	args := []any{p.tenantID}
	if cursor != nil {
		query += " AND (created_at,id)<($2,$3)"
		args = append(args, cursor.CreatedAt, cursor.ID)
	}
	args = append(args, limit+1)
	query += fmt.Sprintf(" ORDER BY created_at DESC,id DESC LIMIT $%d", len(args))
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return ConnectionGrantPage{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	defer rows.Close()
	result := ConnectionGrantPage{Items: make([]ConnectionGrant, 0, limit)}
	for rows.Next() {
		value, scanErr := scanGrant(rows)
		if scanErr != nil {
			return ConnectionGrantPage{}, fail("DATABASE_UNAVAILABLE", 503)
		}
		if len(result.Items) == limit {
			last := result.Items[len(result.Items)-1]
			result.NextCursor = encodeCursor(p, "connection_grants", last.CreatedAt, last.ID)
			break
		}
		result.Items = append(result.Items, value)
	}
	if err = rows.Err(); err != nil {
		return ConnectionGrantPage{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	return result, nil
}
