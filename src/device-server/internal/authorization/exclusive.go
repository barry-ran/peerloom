package authorization

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"strconv"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/identity"
	"github.com/jackc/pgx/v5"
)

// PrepareExclusiveInTx requires the authenticated management tenant transaction
// lock. No caller-supplied epoch, grant, state or lease is accepted.
func PrepareExclusiveInTx(ctx context.Context, tx pgx.Tx, tenant, source, target string, ttl int) (Session, error) {
	if !uuidPattern.MatchString(tenant) || !uuidPattern.MatchString(source) || !uuidPattern.MatchString(target) || source == target || ttl < 1 || ttl > 2592000 {
		return Session{}, failure("INVALID_INPUT", 422)
	}
	from, to, err := loadPeers(ctx, tx, tenant, source, target)
	if err != nil {
		return Session{}, err
	}
	if err = validatePeers(from, to, true); err != nil {
		return Session{}, err
	}
	if !to.exclusive {
		return Session{}, failure("EXCLUSIVE_POLICY_REQUIRED", 409)
	}
	at, err := now(ctx, tx)
	if err != nil {
		return Session{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO exclusive_targets(tenant_id,target_device_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, tenant, target); err != nil {
		return Session{}, databaseError(err)
	}
	var epoch int64
	var previous *string
	var release time.Time
	var fenced bool
	err = tx.QueryRow(ctx, `SELECT epoch,session_id::text,release_not_before,target_fenced FROM exclusive_targets WHERE tenant_id=$1 AND target_device_id=$2 FOR UPDATE`, tenant, target).Scan(&epoch, &previous, &release, &fenced)
	if err != nil {
		return Session{}, databaseError(err)
	}
	if previous != nil && !fenced && release.After(at) {
		return Session{}, failure("TARGET_OCCUPIED", 409)
	}
	if epoch == 9223372036854775807 {
		return Session{}, failure("EXCLUSIVE_EPOCH_EXHAUSTED", 409)
	}
	// A previously issued non-exclusive lease must also have elapsed before the
	// application policy can grant a new owner. Policy toggles cannot bypass it.
	var legacy bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sessions WHERE tenant_id=$1 AND target_device_id=$2 AND target_epoch=0 AND GREATEST(source_lease_expires_at,target_lease_expires_at)+interval '2 seconds'>clock_timestamp())`, tenant, target).Scan(&legacy)
	if err != nil {
		return Session{}, databaseError(err)
	}
	if legacy {
		return Session{}, failure("TARGET_OCCUPIED", 409)
	}
	for _, peer := range []peer{from, to} {
		if peer.limit == -1 {
			continue
		}
		var count int
		err = tx.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE tenant_id=$1 AND state<>'closed' AND source_lease_expires_at>clock_timestamp() AND target_lease_expires_at>clock_timestamp() AND (source_device_id=$2 OR target_device_id=$2)`, tenant, peer.id).Scan(&count)
		if err != nil {
			return Session{}, databaseError(err)
		}
		if count >= peer.limit {
			return Session{}, failure("CONCURRENCY_LIMIT", 429)
		}
	}
	if previous != nil {
		if _, err = tx.Exec(ctx, `UPDATE sessions SET state='closed',close_reason=COALESCE(close_reason,'EXCLUSIVE_LEASE_EXPIRED'),closed_at=COALESCE(closed_at,clock_timestamp()) WHERE tenant_id=$1 AND id=$2 AND state<>'closed'`, tenant, *previous); err != nil {
			return Session{}, databaseError(err)
		}
	}
	expires := at.Add(time.Duration(ttl) * time.Second)
	deadline := at.Add(30 * time.Second)
	if expires.Before(deadline) {
		deadline = expires
	}
	epoch++
	if _, err = tx.Exec(ctx, `UPDATE exclusive_targets SET epoch=$3,session_id=NULL,owner_device_id=$4,release_not_before=$5,target_fenced=false WHERE tenant_id=$1 AND target_device_id=$2`, tenant, target, epoch, source, deadline.Add(2*time.Second)); err != nil {
		return Session{}, databaseError(err)
	}
	var grantID string
	err = tx.QueryRow(ctx, `INSERT INTO connection_grants(tenant_id,source_device_id,target_device_id,expires_at,expiry_action,max_sessions) VALUES($1,$2,$3,$4,'terminate',1) RETURNING id::text`, tenant, source, target, expires).Scan(&grantID)
	if err != nil {
		return Session{}, databaseError(err)
	}
	result, err := scanSession(tx.QueryRow(ctx, `INSERT INTO sessions(tenant_id,source_device_id,target_device_id,grant_id,state,request_id,source_lease_expires_at,target_lease_expires_at,lease_generation,target_epoch,prepared,connect_deadline,exclusive_release_not_before) VALUES($1,$2,$3,$4,'authorizing',gen_random_uuid(),$5,$5,1,$6,true,$5,$7) RETURNING `+sessionColumns, tenant, source, target, grantID, deadline, epoch, deadline.Add(2*time.Second)))
	if err != nil {
		return Session{}, databaseError(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE exclusive_targets SET session_id=$3 WHERE tenant_id=$1 AND target_device_id=$2 AND epoch=$4`, tenant, target, result.ID, epoch); err != nil {
		return Session{}, databaseError(err)
	}
	return result, nil
}

func canonicalEpoch(value string) bool {
	n, err := strconv.ParseInt(value, 10, 64)
	return err == nil && n > 0 && strconv.FormatInt(n, 10) == value
}

// CheckEpoch authenticates a mutation's epoch before the existing operation.
// The operation also checks ownership inside its own transaction, so a race
// between these two checks cannot revive a superseded session.
func (s *Service) CheckEpoch(ctx context.Context, actor identity.Device, id, epoch string) error {
	value, err := s.Get(ctx, actor, id)
	if err != nil {
		return err
	}
	if value.ExclusiveTarget {
		if !canonicalEpoch(epoch) || epoch != value.TargetEpoch {
			return failure("EXCLUSIVE_EPOCH_STALE", 409)
		}
	} else if epoch != "" {
		return failure("INVALID_INPUT", 422)
	}
	return nil
}

func validateExclusiveTx(ctx context.Context, tx pgx.Tx, value Session) error {
	if !value.ExclusiveTarget {
		return nil
	}
	var current string
	var session *string
	var fenced bool
	err := tx.QueryRow(ctx, `SELECT epoch::text,session_id::text,target_fenced FROM exclusive_targets WHERE tenant_id=$1 AND target_device_id=$2 FOR UPDATE`, value.TenantID, value.TargetDeviceID).Scan(&current, &session, &fenced)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return failure("EXCLUSIVE_EPOCH_STALE", 409)
		}
		return databaseError(err)
	}
	if current != value.TargetEpoch || session == nil || *session != value.ID || fenced {
		return failure("EXCLUSIVE_EPOCH_STALE", 409)
	}
	return nil
}

func (s *Service) ConnectPrepared(ctx context.Context, actor identity.Device, id string) (Session, error) {
	return s.operate(ctx, actor, id, false, func(ctx context.Context, tx pgx.Tx, value Session, _ grant, at time.Time) (Session, error) {
		if !value.ExclusiveTarget || actor.ID != value.SourceDeviceID {
			return Session{}, failure("SOURCE_ONLY", 403)
		}
		if !value.Prepared {
			return value, nil
		}
		if value.ConnectDeadline == nil || !value.ConnectDeadline.After(at) {
			return Session{}, failure("PREPARED_EXPIRED", 409)
		}
		result, err := scanSession(tx.QueryRow(ctx, `UPDATE sessions SET prepared=false WHERE tenant_id=$1 AND id=$2 RETURNING `+sessionColumns, value.TenantID, value.ID))
		if err != nil {
			return Session{}, databaseError(err)
		}
		return result, nil
	})
}

// FenceAck is only a target acknowledgement AFTER its SDK gate and stream
// workers have stopped. A source close or an acknowledgement for an old epoch
// must never release a newer owner's reservation.
func (s *Service) FenceAck(ctx context.Context, actor identity.Device, id, epoch string) (Session, error) {
	if !validActor(actor) || !uuidPattern.MatchString(id) || !canonicalEpoch(epoch) {
		return Session{}, failure("INVALID_INPUT", 422)
	}
	tx, err := s.begin(ctx, actor.TenantID)
	if err != nil {
		return Session{}, err
	}
	defer rollback(tx)
	value, err := loadSession(ctx, tx, actor.TenantID, id)
	if err != nil {
		return Session{}, err
	}
	if !value.ExclusiveTarget || value.TargetDeviceID != actor.ID {
		return Session{}, failure("TARGET_ONLY", 403)
	}
	if value.TargetEpoch != epoch {
		return Session{}, failure("EXCLUSIVE_EPOCH_STALE", 409)
	}
	if value.State != "closed" {
		return Session{}, failure("FENCE_NOT_REQUESTED", 409)
	}
	authority, _ := ctx.Value(exclusiveAuthorityKey{}).(exclusiveAuthority)
	var acceptedFence []byte
	if err = tx.QueryRow(ctx, `SELECT target_accept_fence_hash FROM sessions WHERE tenant_id=$1 AND id=$2`, actor.TenantID, id).Scan(&acceptedFence); err != nil {
		return Session{}, databaseError(err)
	}
	if len(acceptedFence) != 32 || len(authority.fenceHash) != 32 || subtle.ConstantTimeCompare(acceptedFence, authority.fenceHash) != 1 {
		return Session{}, failure("EXCLUSIVE_FENCE_STALE", 409)
	}
	if err = checkExclusiveAuthority(ctx, value, false); err != nil {
		return Session{}, err
	}

	// Updating the historical row is safe, but can only release its own resource.
	if _, err = tx.Exec(ctx, `UPDATE exclusive_targets SET target_fenced=true WHERE tenant_id=$1 AND target_device_id=$2 AND epoch=$3::bigint AND session_id=$4`, value.TenantID, value.TargetDeviceID, epoch, value.ID); err != nil {
		return Session{}, databaseError(err)
	}
	value, err = scanSession(tx.QueryRow(ctx, `UPDATE sessions SET target_fenced=true WHERE tenant_id=$1 AND id=$2 RETURNING `+sessionColumns, value.TenantID, value.ID))
	if err != nil {
		return Session{}, databaseError(err)
	}
	if err = verifyCurrentExclusiveFence(ctx); err != nil {
		return Session{}, err
	}
	if err = commit(ctx, tx); err != nil {
		return Session{}, err
	}
	return value, nil
}

// WithExclusiveAuthority is populated only after the transport has verified the
// current authenticated WSS owner. HTTP ICE supplies epoch but no runtime fence.
func WithExclusiveAuthority(ctx context.Context, epoch, fence string) context.Context {
	a := exclusiveAuthority{epoch: epoch}
	if fence != "" {
		h := sha256.Sum256([]byte(fence))
		a.fenceHash = h[:]
	}
	return context.WithValue(ctx, exclusiveAuthorityKey{}, a)
}

type exclusiveAuthorityKey struct{}
type exclusiveAuthority struct {
	epoch     string
	fenceHash []byte
}

func checkExclusiveAuthority(ctx context.Context, value Session, readOnly bool) error {
	a, _ := ctx.Value(exclusiveAuthorityKey{}).(exclusiveAuthority)
	if !value.ExclusiveTarget {
		if a.epoch != "" {
			return failure("INVALID_INPUT", 422)
		}
		return nil
	}
	if readOnly && a.epoch == "" {
		return nil
	}
	if !canonicalEpoch(a.epoch) || a.epoch != value.TargetEpoch {
		return failure("EXCLUSIVE_EPOCH_STALE", 409)
	}
	return nil
}

// ReadExclusiveInTx returns current persisted state, never a cached authorization.
// Caller owns the authenticated management tenant lock.
func ReadExclusiveInTx(ctx context.Context, tx pgx.Tx, tenant, id string) (Session, error) {
	value, err := loadSession(ctx, tx, tenant, id)
	if err != nil || !value.ExclusiveTarget || value.State == "closed" {
		return value, err
	}
	at, err := now(ctx, tx)
	if err != nil {
		return Session{}, err
	}
	if !value.LeaseExpiresAt.After(at) || (value.State == "authorizing" && (value.ConnectDeadline == nil || !value.ConnectDeadline.After(at))) {
		return closeSession(ctx, tx, value, "PREPARED_OR_LEASE_EXPIRED")
	}
	return value, nil
}

// WithExclusiveFenceCheck lets the WSS transport revalidate current ownership
// immediately before an exclusive accept/ack transaction commits. It is never
// derived from an HTTP header or device-supplied callback.
func WithExclusiveFenceCheck(ctx context.Context, check func(context.Context) error) context.Context {
	return context.WithValue(ctx, exclusiveFenceCheckKey{}, check)
}

type exclusiveFenceCheckKey struct{}

func verifyCurrentExclusiveFence(ctx context.Context) error {
	check, _ := ctx.Value(exclusiveFenceCheckKey{}).(func(context.Context) error)
	if check == nil {
		return failure("EXCLUSIVE_PROTOCOL_REQUIRED", 409)
	}
	return check(ctx)
}
