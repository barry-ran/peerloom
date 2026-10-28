package identity

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// RevokeDeviceTx requires management authorization and the caller's tenant-wide
// authorization lock. It never commits. Lock order matches Refresh: app/tenant,
// device, then credentials. Revocation is irreversible for this installation.
func RevokeDeviceTx(ctx context.Context, tx pgx.Tx, tenantID, deviceID string) error {
	var applicationID string
	err := tx.QueryRow(ctx, "SELECT application_id::text FROM devices WHERE tenant_id=$1 AND id=$2", tenantID, deviceID).Scan(&applicationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Fail("DEVICE_NOT_FOUND", 404)
	}
	if err != nil {
		return Fail("DATABASE_UNAVAILABLE", 503)
	}
	var locked string
	if err = tx.QueryRow(ctx, `SELECT a.id::text FROM applications a JOIN tenants t ON t.id=a.tenant_id
WHERE a.tenant_id=$1 AND a.id=$2 FOR SHARE OF a,t`, tenantID, applicationID).Scan(&locked); err != nil {
		return Fail("DATABASE_UNAVAILABLE", 503)
	}
	if _, err = tx.Exec(ctx, "UPDATE devices SET status='revoked' WHERE tenant_id=$1 AND id=$2", tenantID, deviceID); err != nil {
		return Fail("DATABASE_UNAVAILABLE", 503)
	}
	if _, err = tx.Exec(ctx, "UPDATE device_credentials SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE tenant_id=$1 AND device_id=$2", tenantID, deviceID); err != nil {
		return Fail("DATABASE_UNAVAILABLE", 503)
	}
	return nil
}
