package management

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

// CommitUncertainError requires inspecting persisted material before retry.
type CommitUncertainError struct{ Err error }

func (e *CommitUncertainError) Error() string {
	return fmt.Sprintf("commit outcome uncertain: %v", e.Err)
}
func (e *CommitUncertainError) Unwrap() error { return e.Err }

// SetupResult is secret provisioning material for a trusted business backend.
type SetupResult struct {
	KeyResult
	ApplicationID   string `json:"application_id"`
	TenantName      string `json:"tenant_name"`
	ApplicationName string `json:"application_name"`
}

// SetupEmpty installs the first tenant and application only. It never adopts or
// modifies an existing deployment. persist must durably save the secret before
// commit; on uncertain commit, operators must inspect state, not retry blindly.
func SetupEmpty(ctx context.Context, pool *pgxpool.Pool, name, application string, ttl time.Duration, persist func(SetupResult) error) (SetupResult, error) {
	if !validText(name, 128) || !validText(application, 128) || persist == nil {
		return SetupResult{}, fail("INVALID_SETUP", 422)
	}
	if err := validateKey(ScopeAdmin, ttl, "selfhost-setup"); err != nil {
		return SetupResult{}, err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return SetupResult{}, err
	}
	defer rollback(tx)
	// Serialize with tenant creation, including the existing offline bootstrap.
	if _, err = tx.Exec(ctx, "LOCK TABLE tenants IN EXCLUSIVE MODE"); err != nil {
		return SetupResult{}, err
	}
	var exists bool
	if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM tenants)").Scan(&exists); err != nil {
		return SetupResult{}, err
	}
	if exists {
		return SetupResult{}, fail("SETUP_ALREADY_INITIALIZED", 409)
	}
	var tenant string
	if err = tx.QueryRow(ctx, "INSERT INTO tenants(name) VALUES($1) RETURNING id::text", name).Scan(&tenant); err != nil {
		return SetupResult{}, err
	}
	key, err := issueKey(ctx, tx, tenant, ScopeAdmin, ttl, "selfhost-setup")
	if err != nil {
		return SetupResult{}, err
	}
	result := SetupResult{KeyResult: key, TenantName: name, ApplicationName: application}
	if err = tx.QueryRow(ctx, `INSERT INTO applications(tenant_id,name,registration_mode,require_target_approval,max_connections) VALUES($1,$2,'grant',false,-1) RETURNING id::text`, tenant, application).Scan(&result.ApplicationID); err != nil {
		return SetupResult{}, err
	}
	var operator string
	if err = tx.QueryRow(ctx, "SELECT current_user").Scan(&operator); err != nil {
		return SetupResult{}, err
	}
	if err = recordAudit(ctx, tx, tenant, "offline_operator", operator, "application.create", "application", result.ApplicationID, map[string]any{}); err != nil {
		return SetupResult{}, err
	}
	if err = persist(result); err != nil {
		return SetupResult{}, err
	}
	if err = commit(ctx, tx); err != nil {
		return SetupResult{}, &CommitUncertainError{Err: err}
	}
	return result, nil
}

type KeyStatus struct {
	TenantID     string     `json:"tenant_id"`
	CredentialID string     `json:"credential_id"`
	Scope        Scope      `json:"scope"`
	ExpiresAt    time.Time  `json:"expires_at"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	Expired      bool       `json:"expired"`
	TenantActive bool       `json:"tenant_active"`
}

func InspectKey(ctx context.Context, pool *pgxpool.Pool, tenant, id string) (KeyStatus, error) {
	if !uuidPattern.MatchString(tenant) || !uuidPattern.MatchString(id) {
		return KeyStatus{}, fail("INVALID_INPUT", 422)
	}
	r := KeyStatus{TenantID: tenant, CredentialID: id}
	err := pool.QueryRow(ctx, `SELECT c.scope,c.expires_at,c.revoked_at,c.expires_at<=clock_timestamp(),t.status='active' FROM tenant_service_credentials c JOIN tenants t ON t.id=c.tenant_id WHERE c.tenant_id=$1 AND c.id=$2`, tenant, id).Scan(&r.Scope, &r.ExpiresAt, &r.RevokedAt, &r.Expired, &r.TenantActive)
	return r, err
}

// VerifySetup validates actual secret material and application ownership, not just IDs.
func VerifySetup(ctx context.Context, pool *pgxpool.Pool, input SetupResult) (KeyStatus, error) {
	if !uuidPattern.MatchString(input.TenantID) || !uuidPattern.MatchString(input.CredentialID) || !uuidPattern.MatchString(input.ApplicationID) || len(input.ServiceCredential) > 512 || len(input.ServiceCredential) < 10 {
		return KeyStatus{}, fail("INVALID_SETUP", 422)
	}
	var valid bool
	err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenant_service_credentials c JOIN tenants t ON t.id=c.tenant_id JOIN applications a ON a.tenant_id=t.id WHERE c.tenant_id=$1 AND c.id=$2 AND c.credential_hash=$3 AND a.id=$4 AND a.enabled AND t.name=$5 AND a.name=$6)`, input.TenantID, input.CredentialID, hash(input.ServiceCredential), input.ApplicationID, input.TenantName, input.ApplicationName).Scan(&valid)
	if err != nil {
		return KeyStatus{}, err
	}
	if !valid {
		return KeyStatus{}, fail("SETUP_MATERIAL_INVALID", 403)
	}
	return InspectKey(ctx, pool, input.TenantID, input.CredentialID)
}
