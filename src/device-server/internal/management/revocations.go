package management

import (
	"context"
	"errors"
	"strings"

	"github.com/barry-ran/peerloom/src/device-server/internal/authorization"
	"github.com/barry-ran/peerloom/src/device-server/internal/identity"
	"github.com/jackc/pgx/v5"
)

type Revocation struct {
	ID       string                  `json:"id"`
	Revoked  bool                    `json:"revoked"`
	Sessions []authorization.Session `json:"closed_sessions"`
}

func bridgeError(err error) error {
	var auth *authorization.Error
	if errors.As(err, &auth) {
		return fail(auth.Code, auth.Status)
	}
	var device *identity.Error
	if errors.As(err, &device) {
		return fail(device.Code, device.Status)
	}
	return err
}

// finishMutation persists the typed response and safe audit in the caller's
// transaction. It does not commit or dispatch events.
func (s *Service) finishMutation(ctx context.Context, tx pgx.Tx, p Principal, operation, resource, id string, keyHash, requestHash []byte, result any) error {
	if err := recordAudit(ctx, tx, p.tenantID, "service_credential", p.credentialID, operation, resource, id, map[string]any{}); err != nil {
		return err
	}
	return s.saveReplay(ctx, tx, p, operation, id, 200, keyHash, requestHash, result, nil)
}

func (s *Service) RevokeDevice(ctx context.Context, p Principal, id, key string) (Revocation, error) {
	if !uuidPattern.MatchString(id) {
		return Revocation{}, fail("INVALID_INPUT", 422)
	}
	id = strings.ToLower(id)
	tx, err := s.begin(ctx, p, true)
	if err != nil {
		return Revocation{}, err
	}
	defer rollback(tx)
	var result Revocation
	found, kh, rh, err := s.prepareReplay(ctx, tx, p, "device.revoke", key, id, &result)
	if err != nil || found {
		return result, err
	}
	if err = identity.RevokeDeviceTx(ctx, tx, p.tenantID, id); err != nil {
		return Revocation{}, bridgeError(err)
	}
	sessions, err := authorization.CloseForDeviceTx(ctx, tx, p.tenantID, id, "DEVICE_REVOKED")
	if err != nil {
		return Revocation{}, bridgeError(err)
	}
	result = Revocation{ID: id, Revoked: true, Sessions: sessions}
	if err = s.finishMutation(ctx, tx, p, "device.revoke", "device", id, kh, rh, result); err != nil {
		return Revocation{}, err
	}
	if err = commit(ctx, tx); err != nil {
		return Revocation{}, err
	}
	return result, nil
}

func (s *Service) RevokeConnectionGrant(ctx context.Context, p Principal, id, key string) (Revocation, error) {
	if !uuidPattern.MatchString(id) {
		return Revocation{}, fail("INVALID_INPUT", 422)
	}
	id = strings.ToLower(id)
	tx, err := s.begin(ctx, p, true)
	if err != nil {
		return Revocation{}, err
	}
	defer rollback(tx)
	var result Revocation
	found, kh, rh, err := s.prepareReplay(ctx, tx, p, "connection_grant.revoke", key, id, &result)
	if err != nil || found {
		return result, err
	}
	sessions, err := authorization.RevokeGrantTx(ctx, tx, p.tenantID, id)
	if err != nil {
		// Device admission uses GRANT_REQUIRED, but management resource lookup
		// consistently hides foreign and nonexistent identifiers behind 404.
		var domain *authorization.Error
		if errors.As(err, &domain) && domain.Code == "GRANT_REQUIRED" {
			return Revocation{}, fail("GRANT_NOT_FOUND", 404)
		}
		return Revocation{}, bridgeError(err)
	}
	result = Revocation{ID: id, Revoked: true, Sessions: sessions}
	if err = s.finishMutation(ctx, tx, p, "connection_grant.revoke", "connection_grant", id, kh, rh, result); err != nil {
		return Revocation{}, err
	}
	if err = commit(ctx, tx); err != nil {
		return Revocation{}, err
	}
	return result, nil
}

func (s *Service) TerminateSession(ctx context.Context, p Principal, id, key string) (authorization.Session, error) {
	if !uuidPattern.MatchString(id) {
		return authorization.Session{}, fail("INVALID_INPUT", 422)
	}
	id = strings.ToLower(id)
	tx, err := s.begin(ctx, p, true)
	if err != nil {
		return authorization.Session{}, err
	}
	defer rollback(tx)
	var result authorization.Session
	found, kh, rh, err := s.prepareReplay(ctx, tx, p, "session.terminate", key, id, &result)
	if err != nil || found {
		return result, err
	}
	result, err = authorization.TerminateSessionTx(ctx, tx, p.tenantID, id, "ADMIN_TERMINATED")
	if err != nil {
		return authorization.Session{}, bridgeError(err)
	}
	if err = s.finishMutation(ctx, tx, p, "session.terminate", "session", id, kh, rh, result); err != nil {
		return authorization.Session{}, err
	}
	if err = commit(ctx, tx); err != nil {
		return authorization.Session{}, err
	}
	return result, nil
}
