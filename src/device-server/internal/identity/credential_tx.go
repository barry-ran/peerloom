package identity

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
)

// AuthenticateCredentialInTx requires the caller to hold application/tenant and
// device locks first, in the same order as Refresh. It adds the credential lock
// and rechecks expiry/revocation without committing the caller's transaction.
func AuthenticateCredentialInTx(ctx context.Context, tx pgx.Tx, actor Device, token string) error {
	if !strings.HasPrefix(token, "dev_") || len(token) != 47 {
		return Fail("AUTH_INVALID", 401)
	}
	var id string
	err := tx.QueryRow(ctx, `SELECT id::text FROM device_credentials
WHERE tenant_id=$1 AND device_id=$2 AND credential_hash=$3 FOR SHARE`, actor.TenantID, actor.ID, digest(token)).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return Fail("AUTH_INVALID", 401)
	}
	if err != nil {
		return Fail("DATABASE_UNAVAILABLE", 503)
	}
	current, err := authenticate(ctx, tx, token)
	if err != nil {
		return err
	}
	if current.ID != actor.ID || current.TenantID != actor.TenantID || current.ApplicationID != actor.ApplicationID {
		return Fail("AUTH_INVALID", 401)
	}
	return nil
}
