package management

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

func normalizeApplication(input ApplicationInput) (ApplicationInput, error) {
	if !validText(input.Name, 128) {
		return input, fail("INVALID_APPLICATION_NAME", 422)
	}
	if input.RegistrationMode == "" {
		input.RegistrationMode = "grant"
	}
	// Direct is an explicit opt-in; the public identity endpoint enforces durable quotas.
	if input.RegistrationMode != "grant" && input.RegistrationMode != "direct" {
		return input, fail("REGISTRATION_MODE_UNSUPPORTED", 422)
	}
	if input.MaxConnections == nil {
		value := -1
		input.MaxConnections = &value
	}
	if *input.MaxConnections < -1 || *input.MaxConnections > 2147483647 {
		return input, fail("INVALID_CONNECTION_LIMIT", 422)
	}
	return input, nil
}

const applicationColumns = "id::text,tenant_id::text,name,registration_mode,require_target_approval,max_connections,enabled,created_at"

type scanner interface{ Scan(...any) error }

func scanApplication(row scanner) (Application, error) {
	var result Application
	err := row.Scan(&result.ID, &result.TenantID, &result.Name, &result.RegistrationMode, &result.RequireTargetApproval, &result.MaxConnections, &result.Enabled, &result.CreatedAt)
	return result, err
}

func (s *Service) CreateApplication(ctx context.Context, p Principal, input ApplicationInput, key string) (Application, error) {
	input, err := normalizeApplication(input)
	if err != nil {
		return Application{}, err
	}
	tx, err := s.begin(ctx, p, true)
	if err != nil {
		return Application{}, err
	}
	defer rollback(tx)
	var result Application
	found, keyHash, requestHash, err := s.prepareReplay(ctx, tx, p, "application.create", key, input, &result)
	if err != nil {
		return Application{}, err
	}
	if found {
		return result, nil
	}
	result, err = scanApplication(tx.QueryRow(ctx, `INSERT INTO applications(tenant_id,name,registration_mode,require_target_approval,max_connections)
VALUES($1,$2,$3,$4,$5) RETURNING `+applicationColumns, p.tenantID, input.Name, input.RegistrationMode, input.RequireTargetApproval, *input.MaxConnections))
	if err != nil {
		return Application{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	if err = recordAudit(ctx, tx, p.tenantID, p.actorType(), p.credentialID, "application.create", "application", result.ID, map[string]any{}); err != nil {
		return Application{}, err
	}
	if err = s.saveReplay(ctx, tx, p, "application.create", result.ID, 201, keyHash, requestHash, result, nil); err != nil {
		return Application{}, err
	}
	if err = commit(ctx, tx); err != nil {
		return Application{}, err
	}
	return result, nil
}

type pageCursor struct {
	Version   int       `json:"v"`
	Tenant    string    `json:"tenant"`
	Resource  string    `json:"resource"`
	CreatedAt time.Time `json:"created_at"`
	ID        string    `json:"id"`
}

func parsePage(p Principal, page Page, resource string) (int, *pageCursor, error) {
	limit := page.Limit
	if limit == 0 {
		limit = 50
	}
	if limit < 1 || limit > 100 {
		return 0, nil, fail("INVALID_PAGE_LIMIT", 422)
	}
	if page.Cursor == "" {
		return limit, nil, nil
	}
	if len(page.Cursor) > 1024 {
		return 0, nil, fail("INVALID_CURSOR", 422)
	}
	data, err := base64.RawURLEncoding.DecodeString(page.Cursor)
	if err != nil {
		return 0, nil, fail("INVALID_CURSOR", 422)
	}
	var cursor pageCursor
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&cursor); err != nil || cursor.Version != 1 || cursor.Tenant != p.tenantID || cursor.Resource != resource || !uuidPattern.MatchString(cursor.ID) || cursor.CreatedAt.IsZero() {
		return 0, nil, fail("INVALID_CURSOR", 422)
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return 0, nil, fail("INVALID_CURSOR", 422)
	}
	return limit, &cursor, nil
}

func encodeCursor(p Principal, resource string, created time.Time, id string) string {
	data, _ := json.Marshal(pageCursor{Version: 1, Tenant: p.tenantID, Resource: resource, CreatedAt: created, ID: id})
	return base64.RawURLEncoding.EncodeToString(data)
}

func (s *Service) ListApplications(ctx context.Context, p Principal, page Page) (ApplicationPage, error) {
	limit, cursor, err := parsePage(p, page, "applications")
	if err != nil {
		return ApplicationPage{}, err
	}
	tx, err := s.begin(ctx, p, false)
	if err != nil {
		return ApplicationPage{}, err
	}
	defer rollback(tx)
	query := "SELECT " + applicationColumns + " FROM applications WHERE tenant_id=$1"
	args := []any{p.tenantID}
	if cursor != nil {
		query += " AND (created_at,id)<($2,$3)"
		args = append(args, cursor.CreatedAt, cursor.ID)
	}
	if cursor == nil {
		query += " ORDER BY created_at DESC,id DESC LIMIT $2"
	} else {
		query += " ORDER BY created_at DESC,id DESC LIMIT $4"
	}
	args = append(args, limit+1)
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return ApplicationPage{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	defer rows.Close()
	result := ApplicationPage{Items: make([]Application, 0, limit)}
	for rows.Next() {
		value, scanErr := scanApplication(rows)
		if scanErr != nil {
			return ApplicationPage{}, fail("DATABASE_UNAVAILABLE", 503)
		}
		if len(result.Items) == limit {
			last := result.Items[len(result.Items)-1]
			result.NextCursor = encodeCursor(p, "applications", last.CreatedAt, last.ID)
			break
		}
		result.Items = append(result.Items, value)
	}
	if err = rows.Err(); err != nil {
		return ApplicationPage{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	return result, nil
}

func (s *Service) GetApplication(ctx context.Context, p Principal, id string) (Application, error) {
	if !uuidPattern.MatchString(id) {
		return Application{}, fail("INVALID_INPUT", 422)
	}
	tx, err := s.begin(ctx, p, false)
	if err != nil {
		return Application{}, err
	}
	defer rollback(tx)
	result, err := scanApplication(tx.QueryRow(ctx, "SELECT "+applicationColumns+" FROM applications WHERE tenant_id=$1 AND id=$2", p.tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Application{}, fail("APPLICATION_NOT_FOUND", 404)
	}
	if err != nil {
		return Application{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	return result, nil
}
