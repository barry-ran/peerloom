package authorization

import (
	"context"
	"errors"
	"strings"

	"github.com/barry-ran/peerloom/src/device-server/internal/identity"
	"github.com/jackc/pgx/v5"
)

func validActor(actor identity.Device) bool {
	return uuidPattern.MatchString(actor.ID) && uuidPattern.MatchString(actor.TenantID) && uuidPattern.MatchString(actor.ApplicationID)
}

// Request uses the authenticated source and a client UUID solely as an
// idempotency key. The caller cannot supply tenant, grant, state or lease values.
func (s *Service) Request(ctx context.Context, actor identity.Device, targetID, requestID string) (Session, error) {
	if !validActor(actor) {
		return Session{}, failure("AUTH_INVALID", 401)
	}
	if !uuidPattern.MatchString(targetID) || !uuidPattern.MatchString(requestID) {
		return Session{}, failure("INVALID_INPUT", 422)
	}
	targetID, requestID = strings.ToLower(targetID), strings.ToLower(requestID)
	if targetID == actor.ID {
		return Session{}, failure("INVALID_INPUT", 422)
	}
	tx, err := s.begin(ctx, actor.TenantID)
	if err != nil {
		return Session{}, err
	}
	defer rollback(tx)
	existing, err := scanSession(tx.QueryRow(ctx, "SELECT "+sessionColumns+" FROM sessions WHERE tenant_id=$1 AND source_device_id=$2 AND request_id=$3", actor.TenantID, actor.ID, requestID))
	if err == nil {
		if existing.TargetDeviceID != targetID {
			return Session{}, failure("IDEMPOTENCY_CONFLICT", 409)
		}
		if err = commit(ctx, tx); err != nil {
			return Session{}, err
		}
		// Recheck current permissions through the same public read path.
		return s.Get(ctx, actor, existing.ID)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Session{}, databaseError(err)
	}
	from, to, err := loadPeers(ctx, tx, actor.TenantID, actor.ID, targetID)
	if err != nil {
		return Session{}, err
	}
	if from.app != actor.ApplicationID {
		return Session{}, failure("AUTH_INVALID", 401)
	}
	if err = validatePeers(from, to, true); err != nil {
		return Session{}, err
	}
	if to.exclusive {
		return Session{}, failure("EXCLUSIVE_PREPARE_REQUIRED", 409)
	}
	var occupied bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM exclusive_targets WHERE tenant_id=$1 AND target_device_id=$2 AND session_id IS NOT NULL AND NOT target_fenced AND release_not_before>clock_timestamp())`, actor.TenantID, targetID).Scan(&occupied); err != nil {
		return Session{}, databaseError(err)
	}
	if occupied {
		return Session{}, failure("TARGET_OCCUPIED", 409)
	}
	online, err := s.presence.Online(ctx, actor.TenantID, targetID)
	if err != nil {
		return Session{}, failure("PRESENCE_UNAVAILABLE", 503)
	}
	if !online {
		return Session{}, failure("TARGET_OFFLINE", 409)
	}
	for _, device := range []peer{from, to} {
		if device.limit == -1 {
			continue
		}
		var count int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE tenant_id=$1 AND state<>'closed'
AND source_lease_expires_at>clock_timestamp() AND target_lease_expires_at>clock_timestamp()
AND (source_device_id=$2 OR target_device_id=$2)`, actor.TenantID, device.id).Scan(&count); err != nil {
			return Session{}, databaseError(err)
		}
		if count >= device.limit {
			return Session{}, failure("CONCURRENCY_LIMIT", 429)
		}
	}
	grants, err := tx.Query(ctx, `SELECT id::text,expires_at,expiry_action,max_sessions,revoked_at FROM connection_grants
WHERE tenant_id=$1 AND source_device_id=$2 AND target_device_id=$3 AND revoked_at IS NULL AND expires_at>clock_timestamp()
ORDER BY expires_at DESC,id FOR UPDATE`, actor.TenantID, actor.ID, targetID)
	if err != nil {
		return Session{}, databaseError(err)
	}
	var candidates []grant
	for grants.Next() {
		var g grant
		if err = grants.Scan(&g.id, &g.expires, &g.action, &g.max, &g.revoked); err != nil {
			grants.Close()
			return Session{}, databaseError(err)
		}
		candidates = append(candidates, g)
	}
	err = grants.Err()
	grants.Close()
	if err != nil {
		return Session{}, databaseError(err)
	}
	if len(candidates) == 0 {
		return Session{}, failure("GRANT_REQUIRED", 403)
	}
	var selected grant
	for _, candidate := range candidates {
		if candidate.max == -1 {
			selected = candidate
			break
		}
		var count int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE tenant_id=$1 AND grant_id=$2 AND state<>'closed'
AND source_lease_expires_at>clock_timestamp() AND target_lease_expires_at>clock_timestamp()`, actor.TenantID, candidate.id).Scan(&count); err != nil {
			return Session{}, databaseError(err)
		}
		if count < candidate.max {
			selected = candidate
			break
		}
	}
	if selected.id == "" {
		return Session{}, failure("CONCURRENCY_LIMIT", 429)
	}
	at, err := now(ctx, tx)
	if err != nil {
		return Session{}, err
	}
	if !selected.expires.After(at) {
		return Session{}, failure("GRANT_EXPIRED", 403)
	}
	state := "connecting"
	deadline := leaseDeadline(selected, at, s.options.LeaseTTL)
	if to.approval {
		state = "authorizing"
		deadline = at.Add(s.options.ApprovalTimeout)
		if selected.expires.Before(deadline) {
			deadline = selected.expires
		}
	}
	result, err := scanSession(tx.QueryRow(ctx, `INSERT INTO sessions
(tenant_id,source_device_id,target_device_id,grant_id,state,request_id,source_lease_expires_at,target_lease_expires_at,lease_generation)
VALUES($1,$2,$3,$4,$5,$6,$7,$7,1) RETURNING `+sessionColumns, actor.TenantID, actor.ID, targetID, selected.id, state, requestID, deadline))
	if err != nil {
		return Session{}, databaseError(err)
	}
	if err = commit(ctx, tx); err != nil {
		return Session{}, err
	}
	return result, nil
}
