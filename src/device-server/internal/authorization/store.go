package authorization

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Service struct {
	pool     *pgxpool.Pool
	presence Presence
	options  Options
}

func New(pool *pgxpool.Pool, presence Presence, options Options) (*Service, error) {
	if pool == nil || presence == nil {
		return nil, errors.New("database and presence are required")
	}
	if err := options.validate(); err != nil {
		return nil, err
	}
	return &Service{pool: pool, presence: presence, options: options}, nil
}

func rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}

func (s *Service) begin(ctx context.Context, tenant string) (pgx.Tx, error) {
	if !uuidPattern.MatchString(tenant) {
		return nil, failure("AUTH_INVALID", 401)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, failure("DATABASE_UNAVAILABLE", 503)
	}
	key := sha256.Sum256([]byte("peerloom-session:" + strings.ToLower(tenant)))
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", int64(binary.BigEndian.Uint64(key[:8]))); err != nil {
		rollback(tx)
		return nil, failure("DATABASE_UNAVAILABLE", 503)
	}
	return tx, nil
}

func databaseError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return failure("SESSION_NOT_FOUND", 404)
	}
	return failure("DATABASE_UNAVAILABLE", 503)
}

func commit(ctx context.Context, tx pgx.Tx) error {
	if err := tx.Commit(ctx); err != nil {
		return failure("COMMIT_UNCERTAIN_RETRY_SAME_KEY", 503)
	}
	return nil
}

func now(ctx context.Context, tx pgx.Tx) (time.Time, error) {
	var value time.Time
	if err := tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&value); err != nil {
		return value, databaseError(err)
	}
	return value, nil
}

const sessionColumns = `id::text,tenant_id::text,source_device_id::text,target_device_id::text,
COALESCE(grant_id::text,''),state,COALESCE(close_reason,''),
COALESCE(source_lease_expires_at,'epoch'::timestamptz),COALESCE(target_lease_expires_at,'epoch'::timestamptz),
lease_generation,source_connected,target_connected,source_offer_seen,target_answer_seen`

type scanner interface{ Scan(...any) error }

func scanSession(row scanner) (Session, error) {
	var result Session
	err := row.Scan(&result.ID, &result.TenantID, &result.SourceDeviceID, &result.TargetDeviceID, &result.GrantID, &result.State, &result.CloseReason, &result.SourceLeaseExpiresAt, &result.TargetLeaseExpiresAt, &result.LeaseGeneration, &result.SourceConnected, &result.TargetConnected, &result.SourceOfferSeen, &result.TargetAnswerSeen)
	if err != nil {
		return result, err
	}
	result.LeaseExpiresAt = result.SourceLeaseExpiresAt
	if result.TargetLeaseExpiresAt.Before(result.LeaseExpiresAt) {
		result.LeaseExpiresAt = result.TargetLeaseExpiresAt
	}
	return result, nil
}

func loadSession(ctx context.Context, tx pgx.Tx, tenant, id string) (Session, error) {
	result, err := scanSession(tx.QueryRow(ctx, "SELECT "+sessionColumns+" FROM sessions WHERE tenant_id=$1 AND id=$2 FOR UPDATE", tenant, id))
	if err != nil {
		return result, databaseError(err)
	}
	return result, nil
}

func closeSession(ctx context.Context, tx pgx.Tx, value Session, reason string) (Session, error) {
	result, err := scanSession(tx.QueryRow(ctx, `UPDATE sessions SET state='closed',close_reason=$1,closed_at=clock_timestamp()
WHERE tenant_id=$2 AND id=$3 RETURNING `+sessionColumns, reason, value.TenantID, value.ID))
	if err != nil {
		return result, databaseError(err)
	}
	return result, nil
}

type peer struct {
	id, app, status                string
	enabled, connectable, approval bool
	limit                          int
}

func loadPeers(ctx context.Context, tx pgx.Tx, tenant, source, target string) (peer, peer, error) {
	rows, err := tx.Query(ctx, `SELECT d.id::text,d.application_id::text,d.status,a.enabled AND t.status='active',
d.connectable,a.require_target_approval,COALESCE(d.max_connections,a.max_connections)
FROM devices d JOIN applications a ON a.id=d.application_id AND a.tenant_id=d.tenant_id
JOIN tenants t ON t.id=d.tenant_id WHERE d.tenant_id=$1 AND d.id IN($2,$3) ORDER BY d.id FOR SHARE OF d,a,t`, tenant, source, target)
	if err != nil {
		return peer{}, peer{}, databaseError(err)
	}
	defer rows.Close()
	var from, to peer
	for rows.Next() {
		var p peer
		if err = rows.Scan(&p.id, &p.app, &p.status, &p.enabled, &p.connectable, &p.approval, &p.limit); err != nil {
			return from, to, databaseError(err)
		}
		if p.id == source {
			from = p
		}
		if p.id == target {
			to = p
		}
	}
	if err = rows.Err(); err != nil {
		return from, to, databaseError(err)
	}
	if from.id == "" {
		return from, to, failure("AUTH_INVALID", 401)
	}
	if to.id == "" {
		return from, to, failure("TARGET_NOT_FOUND", 404)
	}
	return from, to, nil
}

func validatePeers(from, to peer, requireConnectable bool) error {
	if from.status != "active" || !from.enabled {
		return failure("DEVICE_REVOKED", 403)
	}
	if to.status != "active" || !to.enabled || (requireConnectable && !to.connectable) {
		return failure("TARGET_NOT_CONNECTABLE", 403)
	}
	return nil
}

type grant struct {
	id      string
	expires time.Time
	action  string
	max     int
	revoked *time.Time
}

func loadGrant(ctx context.Context, tx pgx.Tx, tenant, id string) (grant, error) {
	var result grant
	err := tx.QueryRow(ctx, `SELECT id::text,expires_at,expiry_action,max_sessions,revoked_at FROM connection_grants
WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, tenant, id).Scan(&result.id, &result.expires, &result.action, &result.max, &result.revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, failure("GRANT_REQUIRED", 403)
	}
	if err != nil {
		return result, databaseError(err)
	}
	return result, nil
}

func grantValid(g grant, value Session, at time.Time) error {
	if g.revoked != nil {
		return failure("GRANT_REVOKED", 403)
	}
	if !g.expires.After(at) && (g.action == "terminate" || value.State == "authorizing" || value.State == "requested") {
		return failure("GRANT_EXPIRED", 403)
	}
	return nil
}

func leaseDeadline(g grant, at time.Time, ttl time.Duration) time.Time {
	until := at.Add(ttl)
	if g.action == "terminate" && g.expires.Before(until) {
		until = g.expires
	}
	return until
}
