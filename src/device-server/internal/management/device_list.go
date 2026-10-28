package management

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

type DeviceFilter struct {
	ApplicationID string
	Online        *bool
	Tags          map[string]any
}

type DevicePage struct {
	Items      []Device `json:"items"`
	NextCursor string   `json:"next_cursor,omitempty"`
}

func (s *Service) ListDevices(ctx context.Context, p Principal, page Page, filter DeviceFilter) (DevicePage, error) {
	filter.ApplicationID = strings.ToLower(filter.ApplicationID)
	if filter.ApplicationID != "" && !uuidPattern.MatchString(filter.ApplicationID) {
		return DevicePage{}, fail("INVALID_INPUT", 422)
	}
	if !validProperties(filter.Tags) {
		return DevicePage{}, fail("INVALID_TAG_FILTER", 422)
	}
	resource := "devices:" + filter.ApplicationID
	var tagJSON []byte
	if filter.Tags != nil {
		tagJSON, _ = json.Marshal(filter.Tags)
		resource += ":tags:" + hex.EncodeToString(hash(string(tagJSON)))
	}
	if filter.Online != nil {
		resource += fmt.Sprintf(":%t", *filter.Online)
		if s.presence == nil {
			return DevicePage{}, fail("PRESENCE_UNAVAILABLE", 503)
		}
	}
	limit, cursor, err := parsePage(p, page, resource)
	if err != nil {
		return DevicePage{}, err
	}
	tx, err := s.begin(ctx, p, false)
	if err != nil {
		return DevicePage{}, err
	}
	defer rollback(tx)
	query := "SELECT " + deviceColumns + " FROM devices WHERE tenant_id=$1"
	args := []any{p.tenantID}
	if filter.ApplicationID != "" {
		args = append(args, filter.ApplicationID)
		query += fmt.Sprintf(" AND application_id=$%d", len(args))
	}
	if filter.Tags != nil {
		args = append(args, tagJSON)
		query += fmt.Sprintf(" AND tags @> $%d::jsonb", len(args))
	}
	if cursor != nil {
		args = append(args, cursor.CreatedAt, cursor.ID)
		query += fmt.Sprintf(" AND (created_at,id)<($%d,$%d)", len(args)-1, len(args))
	}
	budget := limit
	if filter.Online != nil {
		budget = limit * 10
	}
	args = append(args, budget+1)
	query += fmt.Sprintf(" ORDER BY created_at DESC,id DESC LIMIT $%d", len(args))
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return DevicePage{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	candidates := make([]Device, 0, budget+1)
	for rows.Next() {
		value, scanErr := scanDevice(rows)
		if scanErr != nil {
			rows.Close()
			return DevicePage{}, fail("DATABASE_UNAVAILABLE", 503)
		}
		candidates = append(candidates, value)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return DevicePage{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	result := DevicePage{Items: make([]Device, 0, limit)}
	for i, value := range candidates {
		if i == budget || len(result.Items) == limit {
			previous := candidates[i-1]
			result.NextCursor = encodeCursor(p, resource, previous.CreatedAt, previous.ID)
			break
		}
		if err = s.devicePresence(ctx, &value); err != nil {
			return DevicePage{}, err
		}
		if filter.Online == nil || *filter.Online == *value.Online {
			result.Items = append(result.Items, value)
		}
	}
	return result, nil
}
