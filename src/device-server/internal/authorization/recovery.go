package authorization

import (
	"context"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/identity"
	"github.com/jackc/pgx/v5"
)

// RecoverGeneration authenticates the actual bearer again inside the session
// transaction. It never renews leases, changes participants or revives closure.
// Both peers racing with the same expected generation converge on one successor.
func (s *Service) RecoverGeneration(ctx context.Context, actor identity.Device, id, credential string, expected int64) (Session, error) {
	if expected < 1 || expected >= MaxNegotiationGeneration {
		return Session{}, failure("NEGOTIATION_LIMIT", 409)
	}
	return s.operate(ctx, actor, id, false, func(ctx context.Context, tx pgx.Tx, value Session, _ grant, at time.Time) (Session, error) {
		if err := accepted(value); err != nil {
			return Session{}, err
		}
		if err := identity.AuthenticateCredentialInTx(ctx, tx, actor, credential); err != nil {
			return Session{}, err
		}
		if value.NegotiationGeneration == expected+1 {
			return recoveryFence(ctx, tx, actor, credential, value)
		}
		if value.NegotiationGeneration != expected {
			return Session{}, failure("NEGOTIATION_STALE", 409)
		}
		if at.Before(value.NegotiationStartedAt.Add(time.Second)) {
			return Session{}, failure("NEGOTIATION_RATE_LIMIT", 429)
		}
		result, err := scanSession(tx.QueryRow(ctx, `UPDATE sessions SET
negotiation_generation=negotiation_generation+1,negotiation_started_at=clock_timestamp(),
source_offer_seen=false,target_answer_seen=false,source_connected=false,target_connected=false,state='reconnecting'
WHERE tenant_id=$1 AND id=$2 RETURNING `+sessionColumns, value.TenantID, value.ID))
		if err != nil {
			return Session{}, databaseError(err)
		}
		return recoveryFence(ctx, tx, actor, credential, result)
	})
}

// Both a new CAS and its idempotent replay pass the same final time fence.
// Row locks serialize revocation, but waiting on a credential lock can outlive
// the lease validated at the beginning of the operation.
func recoveryFence(ctx context.Context, tx pgx.Tx, actor identity.Device, credential string, value Session) (Session, error) {
	if err := identity.AuthenticateCredentialInTx(ctx, tx, actor, credential); err != nil {
		return Session{}, err
	}
	current, err := now(ctx, tx)
	if err != nil {
		return Session{}, err
	}
	if !value.LeaseExpiresAt.After(current) {
		return Session{}, failure("LEASE_EXPIRED", 403)
	}
	return value, nil
}
