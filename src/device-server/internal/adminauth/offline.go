package adminauth

import (
	"context"
	"errors"
	"github.com/barry-ran/peerloom/src/device-server/internal/authorization"
	"github.com/barry-ran/peerloom/src/device-server/internal/management"
	"github.com/jackc/pgx/v5/pgxpool"
	"strings"
)

// CreateUser requires an explicit trusted offline database operator. It never
// creates a tenant, returns passwords, or silently changes an existing account.
func CreateUser(ctx context.Context, pool *pgxpool.Pool, tenant, username, password string, scope management.Scope) (string, error) {
	username = strings.ToLower(username)
	if !uuidPattern.MatchString(tenant) || !userPattern.MatchString(username) || (scope != management.ScopeAdmin && scope != management.ScopeRead) {
		return "", problem("INVALID_ADMIN_USER", 422)
	}
	encoded, err := HashPassword(password)
	if err != nil {
		return "", err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return "", problem("AUTH_UNAVAILABLE", 503)
	}
	defer rollback(tx)
	if err = authorization.LockTenant(ctx, tx, tenant); err != nil {
		return "", problem("AUTH_UNAVAILABLE", 503)
	}
	var id string
	err = tx.QueryRow(ctx, `INSERT INTO admin_users(tenant_id,username,password_hash,scope) SELECT id,$2,$3,$4 FROM tenants WHERE id=$1 AND status='active' RETURNING id::text`, tenant, username, encoded, scope).Scan(&id)
	if err != nil {
		return "", errors.New("cannot create administrator: tenant unavailable or username already exists")
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,actor_type,actor_id,action,resource_type,resource_id,details) VALUES($1,'database_operator',current_user,'admin.user.create','admin_user',$2,jsonb_build_object('scope',$3::text))`, tenant, id, string(scope)); err != nil {
		return "", problem("AUTH_UNAVAILABLE", 503)
	}
	if err = tx.Commit(ctx); err != nil {
		return "", problem("AUTH_UNAVAILABLE", 503)
	}
	return id, nil
}

// ChangeUser changes only the specified tenant user and revokes every login
// session in the same transaction, including on role changes and password reset.
func ChangeUser(ctx context.Context, pool *pgxpool.Pool, tenant, userID, password string, scope management.Scope, disable bool) error {
	var enabled *bool
	if disable {
		value := false
		enabled = &value
	}
	return UpdateUser(ctx, pool, tenant, userID, UserChange{Password: password, Scope: scope, Enabled: enabled})
}

// UserChange distinguishes unchanged enablement (nil) from an explicit enable or
// disable. Every accepted change revokes all existing sessions atomically.
type UserChange struct {
	Password string
	Scope    management.Scope
	Enabled  *bool
}

func UpdateUser(ctx context.Context, pool *pgxpool.Pool, tenant, userID string, change UserChange) error {
	password, scope := change.Password, change.Scope
	if !uuidPattern.MatchString(tenant) || !uuidPattern.MatchString(userID) || (scope != "" && scope != management.ScopeRead && scope != management.ScopeAdmin) {
		return problem("INVALID_ADMIN_USER", 422)
	}
	if password == "" && scope == "" && change.Enabled == nil {
		return problem("INVALID_ADMIN_USER", 422)
	}
	encoded := ""
	var err error
	if password != "" {
		encoded, err = HashPassword(password)
		if err != nil {
			return err
		}
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return problem("AUTH_UNAVAILABLE", 503)
	}
	defer rollback(tx)
	if err = authorization.LockTenant(ctx, tx, tenant); err != nil {
		return problem("AUTH_UNAVAILABLE", 503)
	}
	command, err := tx.Exec(ctx, `UPDATE admin_users SET password_hash=CASE WHEN $3='' THEN password_hash ELSE $3 END,scope=CASE WHEN $4='' THEN scope ELSE $4 END,enabled=COALESCE($5::boolean,enabled),updated_at=clock_timestamp() WHERE id=$1 AND tenant_id=$2`, userID, tenant, encoded, string(scope), change.Enabled)
	if err != nil {
		return problem("AUTH_UNAVAILABLE", 503)
	}
	if command.RowsAffected() != 1 {
		return problem("ADMIN_USER_NOT_FOUND", 404)
	}
	if _, err = tx.Exec(ctx, `DELETE FROM admin_sessions WHERE user_id=$1 AND tenant_id=$2`, userID, tenant); err != nil {
		return problem("AUTH_UNAVAILABLE", 503)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_events(tenant_id,actor_type,actor_id,action,resource_type,resource_id,details) VALUES($1,'database_operator',current_user,'admin.user.change','admin_user',$2,'{}')`, tenant, userID); err != nil {
		return problem("AUTH_UNAVAILABLE", 503)
	}
	if tx.Commit(ctx) != nil {
		return problem("AUTH_UNAVAILABLE", 503)
	}
	return nil
}
func (s *Service) PurgeExpired(ctx context.Context) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return problem("AUTH_UNAVAILABLE", 503)
	}
	defer rollback(tx)
	// Bounded batches: cleanup cannot monopolize the server on a large database.
	for _, query := range []string{
		`DELETE FROM admin_sessions WHERE id IN (SELECT id FROM admin_sessions WHERE expires_at<=clock_timestamp() LIMIT 1000)`,
		`DELETE FROM admin_login_windows WHERE ctid IN (SELECT ctid FROM admin_login_windows WHERE window_start<clock_timestamp()-interval '15 minutes' LIMIT 1000)`,
		`UPDATE admin_management_requests SET response_nonce=NULL,response_ciphertext=NULL WHERE ctid IN (SELECT ctid FROM admin_management_requests WHERE response_expires_at<=clock_timestamp() AND response_ciphertext IS NOT NULL LIMIT 1000)`,
		`DELETE FROM admin_management_requests WHERE ctid IN (SELECT ctid FROM admin_management_requests WHERE expires_at<=clock_timestamp() LIMIT 1000)`,
	} {
		if _, err = tx.Exec(ctx, query); err != nil {
			return problem("AUTH_UNAVAILABLE", 503)
		}
	}
	if tx.Commit(ctx) != nil {
		return problem("AUTH_UNAVAILABLE", 503)
	}
	return nil
}
