package management

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func validateKey(scope Scope, ttl time.Duration, label string) error {
	if scope != ScopeRead && scope != ScopeAdmin {
		return fail("INVALID_SCOPE", 422)
	}
	if ttl < time.Minute || ttl > 30*24*time.Hour {
		return fail("INVALID_KEY_TTL", 422)
	}
	if !validText(label, 128) {
		return fail("INVALID_LABEL", 422)
	}
	return nil
}

// BootstrapKey requires trusted offline database access. No HTTP route invokes it.
func BootstrapKey(ctx context.Context, pool *pgxpool.Pool, name string, scope Scope, ttl time.Duration, label string) (KeyResult, error) {
	if !validText(name, 128) {
		return KeyResult{}, fail("INVALID_TENANT_NAME", 422)
	}
	if err := validateKey(scope, ttl, label); err != nil {
		return KeyResult{}, err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return KeyResult{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	defer rollback(tx)
	var tenant string
	if err = tx.QueryRow(ctx, "INSERT INTO tenants(name) VALUES($1) RETURNING id::text", name).Scan(&tenant); err != nil {
		return KeyResult{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	result, err := issueKey(ctx, tx, tenant, scope, ttl, label)
	if err != nil {
		return KeyResult{}, err
	}
	if err = commit(ctx, tx); err != nil {
		return KeyResult{}, err
	}
	return result, nil
}

// IssueKey never adopts an unverified request tenant; only the explicit offline
// CLI calls this function using operator-selected database credentials.
func IssueKey(ctx context.Context, pool *pgxpool.Pool, tenant string, scope Scope, ttl time.Duration, label string) (KeyResult, error) {
	if !uuidPattern.MatchString(tenant) {
		return KeyResult{}, fail("INVALID_TENANT", 422)
	}
	if err := validateKey(scope, ttl, label); err != nil {
		return KeyResult{}, err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return KeyResult{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	defer rollback(tx)
	var status string
	if err = tx.QueryRow(ctx, "SELECT status FROM tenants WHERE id=$1 FOR SHARE", tenant).Scan(&status); errors.Is(err, pgx.ErrNoRows) {
		return KeyResult{}, fail("TENANT_NOT_FOUND", 404)
	} else if err != nil {
		return KeyResult{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	if status != "active" {
		return KeyResult{}, fail("TENANT_DISABLED", 403)
	}
	result, err := issueKey(ctx, tx, tenant, scope, ttl, label)
	if err != nil {
		return KeyResult{}, err
	}
	if err = commit(ctx, tx); err != nil {
		return KeyResult{}, err
	}
	return result, nil
}

func issueKey(ctx context.Context, tx pgx.Tx, tenant string, scope Scope, ttl time.Duration, label string) (KeyResult, error) {
	secret, err := token("svc_")
	if err != nil {
		return KeyResult{}, err
	}
	var result KeyResult
	result.TenantID, result.Scope = tenant, scope
	err = tx.QueryRow(ctx, `INSERT INTO tenant_service_credentials(tenant_id,credential_hash,scope,label,expires_at)
VALUES($1,$2,$3,$4,clock_timestamp()+$5::bigint*interval '1 second') RETURNING id::text,expires_at`, tenant, hash(secret), scope, label, int64(ttl/time.Second)).Scan(&result.CredentialID, &result.ExpiresAt)
	if err != nil {
		return KeyResult{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	var operator string
	if err = tx.QueryRow(ctx, "SELECT current_user").Scan(&operator); err != nil {
		return KeyResult{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	if err = recordAudit(ctx, tx, tenant, "offline_operator", operator, "service_key.issue", "service_credential", result.CredentialID, map[string]any{"scope": scope, "expires_at": result.ExpiresAt}); err != nil {
		return KeyResult{}, err
	}
	result.ServiceCredential = secret
	return result, nil
}

func RevokeKey(ctx context.Context, pool *pgxpool.Pool, tenant, id string) error {
	if !uuidPattern.MatchString(tenant) || !uuidPattern.MatchString(id) {
		return fail("INVALID_INPUT", 422)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fail("DATABASE_UNAVAILABLE", 503)
	}
	defer rollback(tx)
	var revoked *time.Time
	err = tx.QueryRow(ctx, "SELECT revoked_at FROM tenant_service_credentials WHERE tenant_id=$1 AND id=$2 FOR UPDATE", tenant, id).Scan(&revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return fail("SERVICE_KEY_NOT_FOUND", 404)
	}
	if err != nil {
		return fail("DATABASE_UNAVAILABLE", 503)
	}
	if revoked != nil {
		return nil
	}
	if _, err = tx.Exec(ctx, "UPDATE tenant_service_credentials SET revoked_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2", tenant, id); err != nil {
		return fail("DATABASE_UNAVAILABLE", 503)
	}
	var operator string
	if err = tx.QueryRow(ctx, "SELECT current_user").Scan(&operator); err != nil {
		return fail("DATABASE_UNAVAILABLE", 503)
	}
	if err = recordAudit(ctx, tx, tenant, "offline_operator", operator, "service_key.revoke", "service_credential", id, map[string]any{}); err != nil {
		return err
	}
	return commit(ctx, tx)
}
