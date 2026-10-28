package authorization

import (
	"context"

	"github.com/barry-ran/peerloom/src/device-server/internal/tenantlock"
	"github.com/jackc/pgx/v5"
)

// LockTenant must be acquired before business row locks. All transaction helpers
// below require this lock and leave commit/rollback and post-commit delivery to callers.
func LockTenant(ctx context.Context, tx pgx.Tx, tenantID string) error {
	if !uuidPattern.MatchString(tenantID) {
		return failure("INVALID_INPUT", 422)
	}
	if err := tenantlock.Acquire(ctx, tx, tenantID); err != nil {
		return failure("DATABASE_UNAVAILABLE", 503)
	}
	return nil
}

func collectSessions(rows pgx.Rows, err error) ([]Session, error) {
	if err != nil {
		return nil, databaseError(err)
	}
	defer rows.Close()
	result := make([]Session, 0)
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

func CloseForDeviceTx(ctx context.Context, tx pgx.Tx, tenantID, deviceID, reason string) ([]Session, error) {
	return collectSessions(tx.Query(ctx, `UPDATE sessions SET state='closed',close_reason=$3,closed_at=clock_timestamp()
WHERE tenant_id=$1 AND (source_device_id=$2 OR target_device_id=$2) AND state<>'closed' RETURNING `+sessionColumns, tenantID, deviceID, reason))
}

func CloseForApplicationTx(ctx context.Context, tx pgx.Tx, tenantID, applicationID, reason string) ([]Session, error) {
	return collectSessions(tx.Query(ctx, `UPDATE sessions SET state='closed',close_reason=$3,closed_at=clock_timestamp()
WHERE tenant_id=$1 AND state<>'closed' AND (source_device_id IN(SELECT id FROM devices WHERE tenant_id=$1 AND application_id=$2)
OR target_device_id IN(SELECT id FROM devices WHERE tenant_id=$1 AND application_id=$2)) RETURNING `+sessionColumns, tenantID, applicationID, reason))
}

func RevokeGrantTx(ctx context.Context, tx pgx.Tx, tenantID, grantID string) ([]Session, error) {
	if _, err := loadGrant(ctx, tx, tenantID, grantID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, "UPDATE connection_grants SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE tenant_id=$1 AND id=$2", tenantID, grantID); err != nil {
		return nil, databaseError(err)
	}
	return collectSessions(tx.Query(ctx, `UPDATE sessions SET state='closed',close_reason='GRANT_REVOKED',closed_at=clock_timestamp()
WHERE tenant_id=$1 AND grant_id=$2 AND state<>'closed' RETURNING `+sessionColumns, tenantID, grantID))
}

func TerminateSessionTx(ctx context.Context, tx pgx.Tx, tenantID, sessionID, reason string) (Session, error) {
	value, err := loadSession(ctx, tx, tenantID, sessionID)
	if err != nil || value.State == "closed" {
		return value, err
	}
	return closeSession(ctx, tx, value, reason)
}
