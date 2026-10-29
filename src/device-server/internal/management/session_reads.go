package management

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
)

type Session struct {
	ExclusiveTarget          bool       `json:"exclusive_target,omitempty"`
	ExclusiveProtocolVersion int        `json:"exclusive_protocol_version,omitempty"`
	TargetEpoch              string     `json:"target_epoch,omitempty"`
	Prepared                 *bool      `json:"prepared,omitempty"`
	ConnectDeadline          *time.Time `json:"connect_deadline,omitempty"`
	ExclusiveReleaseState    string     `json:"exclusive_release_state,omitempty"`
	ReleaseNotBefore         *time.Time `json:"release_not_before,omitempty"`
	FenceRequired            *bool      `json:"fence_required,omitempty"`
	TargetFenced             *bool      `json:"target_fenced,omitempty"`
	ID                       string     `json:"id"`
	SourceDeviceID           string     `json:"source_device_id"`
	TargetDeviceID           string     `json:"target_device_id"`
	GrantID                  *string    `json:"grant_id"`
	State                    string     `json:"state"`
	LeaseGeneration          int64      `json:"lease_generation"`
	CloseReason              *string    `json:"close_reason"`
	SourceLeaseExpiresAt     *time.Time `json:"source_lease_expires_at"`
	TargetLeaseExpiresAt     *time.Time `json:"target_lease_expires_at"`
	CreatedAt                time.Time  `json:"created_at"`
}

// Read-only list projection uses database time even before the sweeper runs.
const exclusiveExpiredSQL = "target_epoch>0 AND state<>'closed' AND (source_lease_expires_at<=clock_timestamp() OR target_lease_expires_at<=clock_timestamp() OR (state='authorizing' AND connect_deadline<=clock_timestamp()))"
const sessionReadColumns = "id::text,source_device_id::text,target_device_id::text,grant_id::text,CASE WHEN " + exclusiveExpiredSQL + " THEN 'closed' ELSE state END,lease_generation,CASE WHEN " + exclusiveExpiredSQL + " THEN 'PREPARED_OR_LEASE_EXPIRED' ELSE close_reason END,source_lease_expires_at,target_lease_expires_at,created_at,target_epoch,prepared,connect_deadline,target_fenced,exclusive_release_not_before,CASE WHEN target_epoch=0 THEN '' WHEN state<>'closed' AND NOT (" + exclusiveExpiredSQL + ") THEN 'held' WHEN target_fenced OR exclusive_release_not_before<=clock_timestamp() THEN 'released' ELSE 'closing' END"

func scanSession(row scanner) (Session, error) {
	var value Session
	var epoch int64
	var prepared, fenced bool
	err := row.Scan(&value.ID, &value.SourceDeviceID, &value.TargetDeviceID, &value.GrantID, &value.State, &value.LeaseGeneration, &value.CloseReason, &value.SourceLeaseExpiresAt, &value.TargetLeaseExpiresAt, &value.CreatedAt, &epoch, &prepared, &value.ConnectDeadline, &fenced, &value.ReleaseNotBefore, &value.ExclusiveReleaseState)
	if value.ConnectDeadline != nil {
		utc := value.ConnectDeadline.UTC()
		value.ConnectDeadline = &utc
	}
	if value.ReleaseNotBefore != nil {
		utc := value.ReleaseNotBefore.UTC()
		value.ReleaseNotBefore = &utc
	}
	if epoch > 0 {
		value.ExclusiveTarget = true
		value.ExclusiveProtocolVersion = 1
		value.TargetEpoch = strconv.FormatInt(epoch, 10)
		value.Prepared = &prepared
		value.TargetFenced = &fenced
		required := value.State == "closed" && value.ExclusiveReleaseState == "closing" && !fenced
		value.FenceRequired = &required
	}
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
