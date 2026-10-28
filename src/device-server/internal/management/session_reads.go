package management

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

type Session struct {
	ID                   string     `json:"id"`
	SourceDeviceID       string     `json:"source_device_id"`
	TargetDeviceID       string     `json:"target_device_id"`
	GrantID              *string    `json:"grant_id"`
	State                string     `json:"state"`
	CloseReason          *string    `json:"close_reason"`
	SourceLeaseExpiresAt *time.Time `json:"source_lease_expires_at"`
	TargetLeaseExpiresAt *time.Time `json:"target_lease_expires_at"`
	CreatedAt            time.Time  `json:"created_at"`
}

const sessionReadColumns = "id::text,source_device_id::text,target_device_id::text,grant_id::text,state,close_reason,source_lease_expires_at,target_lease_expires_at,created_at"

func scanSession(row scanner) (Session, error) {
	var value Session
	err := row.Scan(&value.ID, &value.SourceDeviceID, &value.TargetDeviceID, &value.GrantID, &value.State, &value.CloseReason, &value.SourceLeaseExpiresAt, &value.TargetLeaseExpiresAt, &value.CreatedAt)
	return value, err
}

// GetSession reports persisted state; unlike device authorization it grants no
// SDP or data-plane permission and does not renew or silently mutate leases.
func (s *Service) GetSession(ctx context.Context, p Principal, id string) (Session, error) {
	if !uuidPattern.MatchString(id) {
		return Session{}, fail("INVALID_INPUT", 422)
	}
	tx, err := s.begin(ctx, p, false)
	if err != nil {
		return Session{}, err
	}
	defer rollback(tx)
	value, err := scanSession(tx.QueryRow(ctx, "SELECT "+sessionReadColumns+" FROM sessions WHERE tenant_id=$1 AND id=$2", p.tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, fail("SESSION_NOT_FOUND", 404)
	}
	if err != nil {
		return Session{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	return value, nil
}
