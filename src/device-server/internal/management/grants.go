package management

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type ConnectionGrantInput struct {
	SourceDeviceID   string     `json:"source_device_id"`
	TargetDeviceID   string     `json:"target_device_id"`
	ExpiresInSeconds *int       `json:"expires_in_seconds,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	ExpiryAction     string     `json:"expiry_action"`
	MaxSessions      int        `json:"max_sessions"`
}

type ConnectionGrant struct {
	ID             string     `json:"id"`
	TenantID       string     `json:"tenant_id"`
	SourceDeviceID string     `json:"source_device_id"`
	TargetDeviceID string     `json:"target_device_id"`
	ExpiresAt      time.Time  `json:"expires_at"`
	ExpiryAction   string     `json:"expiry_action"`
	MaxSessions    int        `json:"max_sessions"`
	RevokedAt      *time.Time `json:"revoked_at"`
	CreatedAt      time.Time  `json:"created_at"`
}

const grantColumns = "id::text,tenant_id::text,source_device_id::text,target_device_id::text,expires_at,expiry_action,max_sessions,revoked_at,created_at"

func scanGrant(row scanner) (ConnectionGrant, error) {
	var value ConnectionGrant
	err := row.Scan(&value.ID, &value.TenantID, &value.SourceDeviceID, &value.TargetDeviceID, &value.ExpiresAt, &value.ExpiryAction, &value.MaxSessions, &value.RevokedAt, &value.CreatedAt)
	return value, err
}

func normalizeGrant(input ConnectionGrantInput) (ConnectionGrantInput, error) {
	input.SourceDeviceID = strings.ToLower(input.SourceDeviceID)
	input.TargetDeviceID = strings.ToLower(input.TargetDeviceID)
	if !uuidPattern.MatchString(input.SourceDeviceID) || !uuidPattern.MatchString(input.TargetDeviceID) || input.SourceDeviceID == input.TargetDeviceID {
		return input, fail("INVALID_GRANT_PEERS", 422)
	}
	if input.ExpiresAt != nil {
		if input.ExpiresInSeconds != nil {
			return input, fail("AMBIGUOUS_GRANT_EXPIRY", 422)
		}
		utc := input.ExpiresAt.UTC()
		input.ExpiresAt = &utc
	} else if input.ExpiresInSeconds == nil || *input.ExpiresInSeconds < 1 || *input.ExpiresInSeconds > 30*24*3600 {
		return input, fail("INVALID_GRANT_TTL", 422)
	}
	if input.ExpiryAction == "" {
		input.ExpiryAction = "terminate"
	}
	if input.ExpiryAction != "terminate" && input.ExpiryAction != "no_new_connections" {
		return input, fail("INVALID_EXPIRY_ACTION", 422)
	}
	if input.MaxSessions == 0 {
		input.MaxSessions = 1
	}
	if input.MaxSessions < 1 || input.MaxSessions > 1024 {
		return input, fail("INVALID_CONNECTION_LIMIT", 422)
	}
	return input, nil
}

func (s *Service) CreateConnectionGrant(ctx context.Context, p Principal, input ConnectionGrantInput, key string) (ConnectionGrant, error) {
	input, err := normalizeGrant(input)
	if err != nil {
		return ConnectionGrant{}, err
	}
	tx, err := s.begin(ctx, p, true)
	if err != nil {
		return ConnectionGrant{}, err
	}
	defer rollback(tx)
	var result ConnectionGrant
	found, kh, rh, err := s.prepareReplay(ctx, tx, p, "connection_grant.create", key, input, &result)
	if err != nil || found {
		return result, err
	}
	// Tenant admission lock serializes device/grant administration and requests.
	// Share-lock both applications before devices, matching identity refresh.
	rows, err := tx.Query(ctx, `SELECT a.id FROM applications a WHERE a.tenant_id=$1 AND a.id IN
(SELECT application_id FROM devices WHERE tenant_id=$1 AND id IN($2,$3)) ORDER BY a.id FOR SHARE`, p.tenantID, input.SourceDeviceID, input.TargetDeviceID)
	if err != nil {
		return ConnectionGrant{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return ConnectionGrant{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	var valid int
	err = tx.QueryRow(ctx, `SELECT count(*) FROM devices d JOIN applications a ON a.id=d.application_id AND a.tenant_id=d.tenant_id
WHERE d.tenant_id=$1 AND d.id IN($2,$3) AND d.status='active' AND a.enabled`, p.tenantID, input.SourceDeviceID, input.TargetDeviceID).Scan(&valid)
	if err != nil {
		return ConnectionGrant{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	if valid != 2 {
		return ConnectionGrant{}, fail("DEVICE_NOT_FOUND", 404)
	}
	var databaseNow time.Time
	if err = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&databaseNow); err != nil {
		return ConnectionGrant{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	var expiresAt time.Time
	if input.ExpiresAt != nil {
		expiresAt = *input.ExpiresAt
	} else {
		expiresAt = databaseNow.Add(time.Duration(*input.ExpiresInSeconds) * time.Second)
	}
	if !expiresAt.After(databaseNow) || expiresAt.After(databaseNow.Add(30*24*time.Hour)) {
		return ConnectionGrant{}, fail("INVALID_GRANT_TTL", 422)
	}
	result, err = scanGrant(tx.QueryRow(ctx, `INSERT INTO connection_grants(tenant_id,source_device_id,target_device_id,expires_at,expiry_action,max_sessions)
VALUES($1,$2,$3,$4,$5,$6) RETURNING `+grantColumns, p.tenantID, input.SourceDeviceID, input.TargetDeviceID, expiresAt, input.ExpiryAction, input.MaxSessions))
	if err != nil {
		return ConnectionGrant{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	if err = recordAudit(ctx, tx, p.tenantID, p.actorType(), p.credentialID, "connection_grant.create", "connection_grant", result.ID, map[string]any{"source_device_id": input.SourceDeviceID, "target_device_id": input.TargetDeviceID}); err != nil {
		return ConnectionGrant{}, err
	}
	if err = s.saveReplay(ctx, tx, p, "connection_grant.create", result.ID, 201, kh, rh, result, nil); err != nil {
		return ConnectionGrant{}, err
	}
	if err = commit(ctx, tx); err != nil {
		return ConnectionGrant{}, err
	}
	return result, nil
}

func (s *Service) GetConnectionGrant(ctx context.Context, p Principal, id string) (ConnectionGrant, error) {
	if !uuidPattern.MatchString(id) {
		return ConnectionGrant{}, fail("INVALID_INPUT", 422)
	}
	tx, err := s.begin(ctx, p, false)
	if err != nil {
		return ConnectionGrant{}, err
	}
	defer rollback(tx)
	result, err := scanGrant(tx.QueryRow(ctx, "SELECT "+grantColumns+" FROM connection_grants WHERE tenant_id=$1 AND id=$2", p.tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return ConnectionGrant{}, fail("GRANT_NOT_FOUND", 404)
	}
	if err != nil {
		return ConnectionGrant{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	return result, nil
}
