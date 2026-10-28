package identity

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type BootstrapResult struct {
	TenantID          string `json:"tenant_id"`
	ApplicationID     string `json:"application_id"`
	RegistrationGrant string `json:"registration_grant"`
	ExpiresAt         string `json:"expires_at"`
}

// BootstrapDevelopment is called only by the explicit local-development CLI.
// There is deliberately no anonymous HTTP management/bootstrap endpoint.
func BootstrapDevelopment(ctx context.Context, pool *pgxpool.Pool, name string) (BootstrapResult, error) {
	if name == "" || len(name) > 128 {
		return BootstrapResult{}, Fail("INVALID_INPUT", 422)
	}
	token, err := randomToken("reg_")
	if err != nil {
		return BootstrapResult{}, Fail("INTERNAL_ERROR", 500)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return BootstrapResult{}, Fail("DATABASE_UNAVAILABLE", 503)
	}
	defer rollback(tx)
	var result BootstrapResult
	if err = tx.QueryRow(ctx, "INSERT INTO tenants(name) VALUES($1) RETURNING id::text", name).Scan(&result.TenantID); err != nil {
		return result, Fail("DATABASE_UNAVAILABLE", 503)
	}
	if err = tx.QueryRow(ctx, "INSERT INTO applications(tenant_id,name,registration_mode) VALUES($1,$2,'grant') RETURNING id::text", result.TenantID, name).Scan(&result.ApplicationID); err != nil {
		return result, Fail("DATABASE_UNAVAILABLE", 503)
	}
	var expires time.Time
	if err = tx.QueryRow(ctx, "INSERT INTO registration_grants(tenant_id,application_id,secret_hash,expires_at) VALUES($1,$2,$3,clock_timestamp()+interval '30 minutes') RETURNING expires_at", result.TenantID, result.ApplicationID, digest(token)).Scan(&expires); err != nil {
		return result, Fail("DATABASE_UNAVAILABLE", 503)
	}
	if err = tx.Commit(ctx); err != nil {
		return result, Fail("COMMIT_UNCERTAIN_INSPECT_DATABASE", 503)
	}
	result.RegistrationGrant = token
	result.ExpiresAt = expires.UTC().Format(time.RFC3339Nano)
	return result, nil
}
