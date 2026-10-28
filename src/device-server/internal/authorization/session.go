package authorization

import (
	"context"
	"strings"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/identity"
	"github.com/jackc/pgx/v5"
)

type operation func(context.Context, pgx.Tx, Session, grant, time.Time) (Session, error)

func (s *Service) operate(ctx context.Context, actor identity.Device, id string, allowClosed bool, fn operation) (Session, error) {
	if !validActor(actor) {
		return Session{}, failure("AUTH_INVALID", 401)
	}
	if !uuidPattern.MatchString(id) {
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
	if actor.ID != value.SourceDeviceID && actor.ID != value.TargetDeviceID {
		return Session{}, failure("SESSION_NOT_FOUND", 404)
	}
	if value.State == "closed" {
		if allowClosed {
			return value, nil
		}
		return value, failure("SESSION_CLOSED", 409)
	}
	from, to, err := loadPeers(ctx, tx, actor.TenantID, value.SourceDeviceID, value.TargetDeviceID)
	if err != nil {
		return Session{}, err
	}
	if (actor.ID == from.id && actor.ApplicationID != from.app) || (actor.ID == to.id && actor.ApplicationID != to.app) {
		return Session{}, failure("AUTH_INVALID", 401)
	}
	closeWithError := func(reason string, cause error) (Session, error) {
		closed, closeErr := closeSession(ctx, tx, value, reason)
		if closeErr != nil {
			return Session{}, closeErr
		}
		if closeErr = commit(ctx, tx); closeErr != nil {
			return Session{}, closeErr
		}
		return closed, cause
	}
	// connectable only controls new acceptance, not an already accepted session.
	if err = validatePeers(from, to, value.State == "requested" || value.State == "authorizing"); err != nil {
		return closeWithError("IDENTITY_OR_POLICY_DISABLED", err)
	}
	if value.GrantID == "" {
		return closeWithError("GRANT_REQUIRED", failure("GRANT_REQUIRED", 403))
	}
	g, err := loadGrant(ctx, tx, actor.TenantID, value.GrantID)
	if err != nil {
		return Session{}, err
	}
	at, err := now(ctx, tx)
	if err != nil {
		return Session{}, err
	}
	if !value.LeaseExpiresAt.After(at) {
		return closeWithError("LEASE_EXPIRED", failure("LEASE_EXPIRED", 403))
	}
	if err = grantValid(g, value, at); err != nil {
		return closeWithError(err.Error(), err)
	}
	result, err := fn(ctx, tx, value, g, at)
	if err != nil {
		return Session{}, err
	}
	if err = commit(ctx, tx); err != nil {
		return Session{}, err
	}
	return result, nil
}

func accepted(value Session) error {
	if value.State != "connecting" && value.State != "connected" && value.State != "reconnecting" {
		return failure("TARGET_APPROVAL_REQUIRED", 403)
	}
	return nil
}

func (s *Service) Get(ctx context.Context, actor identity.Device, id string) (Session, error) {
	return s.operate(ctx, actor, id, true, func(_ context.Context, _ pgx.Tx, value Session, _ grant, _ time.Time) (Session, error) {
		return value, nil
	})
}

// AuthorizeSignal proves participation, accepted state and both live leases.
// The WSS layer additionally validates fencing, negotiation generation and
// offer/answer roles before forwarding to the other returned participant.
func (s *Service) AuthorizeSignal(ctx context.Context, actor identity.Device, id string) (Session, error) {
	return s.operate(ctx, actor, id, false, func(_ context.Context, _ pgx.Tx, value Session, _ grant, _ time.Time) (Session, error) {
		return value, accepted(value)
	})
}

func (s *Service) Respond(ctx context.Context, actor identity.Device, id string, accept bool) (Session, error) {
	if !accept {
		return s.close(ctx, actor, id, "TARGET_REJECTED", true)
	}
	return s.operate(ctx, actor, id, false, func(ctx context.Context, tx pgx.Tx, value Session, g grant, at time.Time) (Session, error) {
		if actor.ID != value.TargetDeviceID {
			return Session{}, failure("TARGET_ONLY", 403)
		}
		if value.State != "authorizing" {
			if err := accepted(value); err != nil {
				return Session{}, err
			}
			return value, nil
		}
		// Pending approval is a new connection even for no_new_connections grants.
		if !g.expires.After(at) {
			return Session{}, failure("GRANT_EXPIRED", 403)
		}
		deadline := leaseDeadline(g, at, s.options.LeaseTTL)
		result, err := scanSession(tx.QueryRow(ctx, `UPDATE sessions SET state='connecting',source_lease_expires_at=$1,
target_lease_expires_at=$1,lease_generation=lease_generation+1 WHERE tenant_id=$2 AND id=$3 RETURNING `+sessionColumns, deadline, value.TenantID, value.ID))
		if err != nil {
			return Session{}, databaseError(err)
		}
		return result, nil
	})
}

func (s *Service) Renew(ctx context.Context, actor identity.Device, id string) (Session, error) {
	return s.operate(ctx, actor, id, false, func(ctx context.Context, tx pgx.Tx, value Session, g grant, at time.Time) (Session, error) {
		if err := accepted(value); err != nil {
			return Session{}, err
		}
		deadline := leaseDeadline(g, at, s.options.LeaseTTL)
		column := "source_lease_expires_at"
		if actor.ID == value.TargetDeviceID {
			column = "target_lease_expires_at"
		}
		result, err := scanSession(tx.QueryRow(ctx, "UPDATE sessions SET "+column+"=$1,lease_generation=lease_generation+1 WHERE tenant_id=$2 AND id=$3 RETURNING "+sessionColumns, deadline, value.TenantID, value.ID))
		if err != nil {
			return Session{}, databaseError(err)
		}
		return result, nil
	})
}

func (s *Service) MarkConnected(ctx context.Context, actor identity.Device, id string) (Session, error) {
	return s.operate(ctx, actor, id, false, func(ctx context.Context, tx pgx.Tx, value Session, _ grant, _ time.Time) (Session, error) {
		if err := accepted(value); err != nil {
			return Session{}, err
		}
		if !value.SourceOfferSeen || !value.TargetAnswerSeen {
			return Session{}, failure("NEGOTIATION_INCOMPLETE", 409)
		}
		if actor.ID == value.SourceDeviceID {
			value.SourceConnected = true
		} else {
			value.TargetConnected = true
		}
		state := "connecting"
		if value.SourceConnected && value.TargetConnected {
			state = "connected"
		}
		result, err := scanSession(tx.QueryRow(ctx, `UPDATE sessions SET source_connected=$1,target_connected=$2,state=$3,
connected_at=CASE WHEN $3='connected' THEN COALESCE(connected_at,clock_timestamp()) ELSE connected_at END
WHERE tenant_id=$4 AND id=$5 RETURNING `+sessionColumns, value.SourceConnected, value.TargetConnected, state, value.TenantID, value.ID))
		if err != nil {
			return Session{}, databaseError(err)
		}
		return result, nil
	})
}

// AuthorizeDescription atomically admits one complete offer and then one answer.
// Initial negotiation generation is fixed at one; no trickle/restart is implied.
func (s *Service) AuthorizeDescription(ctx context.Context, actor identity.Device, id, kind string) (Session, error) {
	return s.operate(ctx, actor, id, false, func(ctx context.Context, tx pgx.Tx, value Session, _ grant, _ time.Time) (Session, error) {
		if err := accepted(value); err != nil {
			return Session{}, err
		}
		column := ""
		switch kind {
		case "session.offer":
			if actor.ID != value.SourceDeviceID {
				return Session{}, failure("SIGNAL_ROLE_FORBIDDEN", 403)
			}
			if value.SourceOfferSeen {
				return Session{}, failure("DESCRIPTION_ALREADY_SENT", 409)
			}
			column = "source_offer_seen"
		case "session.answer":
			if actor.ID != value.TargetDeviceID {
				return Session{}, failure("SIGNAL_ROLE_FORBIDDEN", 403)
			}
			if !value.SourceOfferSeen {
				return Session{}, failure("OFFER_REQUIRED", 409)
			}
			if value.TargetAnswerSeen {
				return Session{}, failure("DESCRIPTION_ALREADY_SENT", 409)
			}
			column = "target_answer_seen"
		default:
			return Session{}, failure("PROTOCOL_UNSUPPORTED", 422)
		}
		result, err := scanSession(tx.QueryRow(ctx, "UPDATE sessions SET "+column+"=true WHERE tenant_id=$1 AND id=$2 RETURNING "+sessionColumns, value.TenantID, value.ID))
		if err != nil {
			return Session{}, databaseError(err)
		}
		return result, nil
	})
}

func (s *Service) MarkReconnecting(ctx context.Context, actor identity.Device, id string) (Session, error) {
	return s.operate(ctx, actor, id, false, func(ctx context.Context, tx pgx.Tx, value Session, _ grant, _ time.Time) (Session, error) {
		if err := accepted(value); err != nil {
			return Session{}, err
		}
		column := "source_connected"
		if actor.ID == value.TargetDeviceID {
			column = "target_connected"
		}
		result, err := scanSession(tx.QueryRow(ctx, "UPDATE sessions SET state='reconnecting',"+column+"=false WHERE tenant_id=$1 AND id=$2 RETURNING "+sessionColumns, value.TenantID, value.ID))
		if err != nil {
			return Session{}, databaseError(err)
		}
		return result, nil
	})
}

func (s *Service) Close(ctx context.Context, actor identity.Device, id, reason string) (Session, error) {
	switch reason {
	case "CLIENT_CLOSED", "TRANSPORT_FAILED":
	default:
		reason = "CLIENT_CLOSED"
	}
	return s.close(ctx, actor, id, reason, false)
}

func (s *Service) close(ctx context.Context, actor identity.Device, id, reason string, targetOnly bool) (Session, error) {
	if !validActor(actor) {
		return Session{}, failure("AUTH_INVALID", 401)
	}
	if !uuidPattern.MatchString(id) {
		return Session{}, failure("INVALID_INPUT", 422)
	}
	tx, err := s.begin(ctx, actor.TenantID)
	if err != nil {
		return Session{}, err
	}
	defer rollback(tx)
	value, err := loadSession(ctx, tx, actor.TenantID, strings.ToLower(id))
	if err != nil {
		return Session{}, err
	}
	if actor.ID != value.SourceDeviceID && actor.ID != value.TargetDeviceID {
		return Session{}, failure("SESSION_NOT_FOUND", 404)
	}
	if targetOnly && actor.ID != value.TargetDeviceID {
		return Session{}, failure("TARGET_ONLY", 403)
	}
	if value.State == "closed" {
		return value, nil
	}
	value, err = closeSession(ctx, tx, value, reason)
	if err != nil {
		return Session{}, err
	}
	if err = commit(ctx, tx); err != nil {
		return Session{}, err
	}
	return value, nil
}
