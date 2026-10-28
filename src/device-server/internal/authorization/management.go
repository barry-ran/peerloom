package authorization

import (
	"context"

	"github.com/barry-ran/peerloom/src/device-server/internal/identity"
)

// RevokeGrant is an internal management operation. The tenant must come from
// separately verified management authorization; never expose it to device WSS.
func (s *Service) RevokeGrant(ctx context.Context, tenantID, grantID string) ([]Session, error) {
	if !uuidPattern.MatchString(tenantID) || !uuidPattern.MatchString(grantID) {
		return nil, failure("INVALID_INPUT", 422)
	}
	tx, err := s.begin(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	if _, err = loadGrant(ctx, tx, tenantID, grantID); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, "UPDATE connection_grants SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE tenant_id=$1 AND id=$2", tenantID, grantID); err != nil {
		return nil, databaseError(err)
	}
	rows, err := tx.Query(ctx, `UPDATE sessions SET state='closed',close_reason='GRANT_REVOKED',closed_at=clock_timestamp()
WHERE tenant_id=$1 AND grant_id=$2 AND state<>'closed' RETURNING `+sessionColumns, tenantID, grantID)
	if err != nil {
		return nil, databaseError(err)
	}
	var result []Session
	for rows.Next() {
		value, scanErr := scanSession(rows)
		if scanErr != nil {
			rows.Close()
			return nil, databaseError(scanErr)
		}
		result = append(result, value)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, databaseError(err)
	}
	if err = commit(ctx, tx); err != nil {
		return nil, err
	}
	return result, nil
}

// Snapshot revalidates active sessions rather than replaying stale memory.
// It fails explicitly instead of silently truncating unusually large accounts.
func (s *Service) Snapshot(ctx context.Context, actor identity.Device) ([]Session, error) {
	if !validActor(actor) {
		return nil, failure("AUTH_INVALID", 401)
	}
	rows, err := s.pool.Query(ctx, `SELECT id::text FROM sessions WHERE tenant_id=$1 AND state<>'closed'
AND (source_device_id=$2 OR target_device_id=$2) ORDER BY created_at,id LIMIT 257`, actor.TenantID, actor.ID)
	if err != nil {
		return nil, databaseError(err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, databaseError(err)
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, databaseError(err)
	}
	if len(ids) > 256 {
		return nil, failure("SNAPSHOT_LIMIT", 429)
	}
	result := make([]Session, 0, len(ids))
	for _, id := range ids {
		value, getErr := s.Get(ctx, actor, id)
		if getErr != nil && value.State != "closed" {
			return nil, getErr
		}
		result = append(result, value)
	}
	return result, nil
}

// SweepExpired is an internal bounded maintenance batch, not a device API.
// Row locks ensure a concurrent successful renewal is rechecked, not overwritten.
func (s *Service) SweepExpired(ctx context.Context) ([]Session, error) {
	rows, err := s.pool.Query(ctx, `WITH expired AS (
SELECT id FROM sessions s WHERE state<>'closed' AND (
source_lease_expires_at IS NULL OR target_lease_expires_at IS NULL OR
source_lease_expires_at<=clock_timestamp() OR target_lease_expires_at<=clock_timestamp() OR
EXISTS(SELECT 1 FROM connection_grants g WHERE g.id=s.grant_id AND g.tenant_id=s.tenant_id
AND (g.revoked_at IS NOT NULL OR (g.expires_at<=clock_timestamp() AND (g.expiry_action='terminate' OR s.state IN('requested','authorizing'))))))
ORDER BY id LIMIT 256 FOR UPDATE SKIP LOCKED)
UPDATE sessions SET state='closed',close_reason='AUTHORIZATION_EXPIRED',closed_at=clock_timestamp()
WHERE id IN(SELECT id FROM expired) RETURNING `+sessionColumns)
	if err != nil {
		return nil, databaseError(err)
	}
	defer rows.Close()
	var result []Session
	for rows.Next() {
		value, scanErr := scanSession(rows)
		if scanErr != nil {
			return nil, databaseError(scanErr)
		}
		result = append(result, value)
	}
	if err = rows.Err(); err != nil {
		return nil, databaseError(err)
	}
	return result, nil
}
