package authorization

import (
	"context"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/identity"
	"github.com/jackc/pgx/v5"
)

// validateSessionTx is shared by ordinary session operations and ICE issuance.
// It neither commits nor changes state; the owning operation controls cleanup.
func validateSessionTx(ctx context.Context, tx pgx.Tx, actor identity.Device, value Session) (grant, time.Time, error) {
	from, to, err := loadPeers(ctx, tx, actor.TenantID, value.SourceDeviceID, value.TargetDeviceID)
	if err != nil {
		return grant{}, time.Time{}, err
	}
	if (actor.ID == from.id && actor.ApplicationID != from.app) || (actor.ID == to.id && actor.ApplicationID != to.app) {
		return grant{}, time.Time{}, failure("AUTH_INVALID", 401)
	}
	if err = validatePeers(from, to, value.State == "requested" || value.State == "authorizing"); err != nil {
		return grant{}, time.Time{}, err
	}
	if value.GrantID == "" {
		return grant{}, time.Time{}, failure("GRANT_REQUIRED", 403)
	}
	g, err := loadGrant(ctx, tx, actor.TenantID, value.GrantID)
	if err != nil {
		return grant{}, time.Time{}, err
	}
	at, err := now(ctx, tx)
	if err != nil {
		return grant{}, time.Time{}, err
	}
	if !value.LeaseExpiresAt.After(at) {
		return grant{}, time.Time{}, failure("LEASE_EXPIRED", 403)
	}
	if err = grantValid(g, value, at); err != nil {
		return grant{}, time.Time{}, err
	}
	return g, at, nil
}

// AuthorizeICEInTx requires LockTenant before all business row locks. It validates
// current participation, acceptance, both leases and grant policy without renewing
// or committing. A denied issuance leaves closure notifications to normal expiry
// maintenance / explicit management revocation; it never silently closes a row.
func (s *Service) AuthorizeICEInTx(ctx context.Context, tx pgx.Tx, actor identity.Device, id string) (Session, error) {
	if !validActor(actor) {
		return Session{}, failure("AUTH_INVALID", 401)
	}
	if !uuidPattern.MatchString(id) {
		return Session{}, failure("INVALID_INPUT", 422)
	}
	value, err := loadSession(ctx, tx, actor.TenantID, id)
	if err != nil {
		return Session{}, err
	}
	if actor.ID != value.SourceDeviceID && actor.ID != value.TargetDeviceID {
		return Session{}, failure("SESSION_NOT_FOUND", 404)
	}
	if value.State == "closed" {
		return Session{}, failure("SESSION_CLOSED", 409)
	}
	if err = accepted(value); err != nil {
		return Session{}, err
	}
	if _, _, err = validateSessionTx(ctx, tx, actor, value); err != nil {
		return Session{}, err
	}
	return value, nil
}
