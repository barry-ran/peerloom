package management

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
)

func (s *Service) IssueRegistrationGrant(ctx context.Context, p Principal, input RegistrationGrantInput, key string) (RegistrationGrant, error) {
	if !uuidPattern.MatchString(input.ApplicationID) {
		return RegistrationGrant{}, fail("INVALID_INPUT", 422)
	}
	input.ApplicationID = strings.ToLower(input.ApplicationID)
	if input.ExpiresInSeconds == 0 {
		input.ExpiresInSeconds = 300
	}
	if input.ExpiresInSeconds < 1 || input.ExpiresInSeconds > 3600 {
		return RegistrationGrant{}, fail("INVALID_GRANT_TTL", 422)
	}
	tx, err := s.begin(ctx, p, true)
	if err != nil {
		return RegistrationGrant{}, err
	}
	defer rollback(tx)
	var result RegistrationGrant
	found, keyHash, requestHash, err := s.prepareReplay(ctx, tx, p, "registration_grant.issue", key, input, &result)
	if err != nil {
		return RegistrationGrant{}, err
	}
	if found {
		return result, nil
	}
	var enabled bool
	var mode string
	err = tx.QueryRow(ctx, "SELECT enabled,registration_mode FROM applications WHERE tenant_id=$1 AND id=$2 FOR SHARE", p.tenantID, input.ApplicationID).Scan(&enabled, &mode)
	if errors.Is(err, pgx.ErrNoRows) {
		return RegistrationGrant{}, fail("APPLICATION_NOT_FOUND", 404)
	}
	if err != nil {
		return RegistrationGrant{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	if !enabled {
		return RegistrationGrant{}, fail("APPLICATION_DISABLED", 403)
	}
	if mode != "grant" && mode != "both" {
		return RegistrationGrant{}, fail("REGISTRATION_MODE_UNSUPPORTED", 422)
	}
	secret, err := token("reg_")
	if err != nil {
		return RegistrationGrant{}, err
	}
	err = tx.QueryRow(ctx, `INSERT INTO registration_grants(tenant_id,application_id,secret_hash,expires_at)
VALUES($1,$2,$3,clock_timestamp()+$4::bigint*interval '1 second') RETURNING id::text,expires_at`, p.tenantID, input.ApplicationID, hash(secret), input.ExpiresInSeconds).Scan(&result.ID, &result.ExpiresAt)
	if err != nil {
		return RegistrationGrant{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	result.Grant = secret
	if err = recordAudit(ctx, tx, p.tenantID, "service_credential", p.credentialID, "registration_grant.issue", "registration_grant", result.ID, map[string]any{"application_id": input.ApplicationID, "expires_at": result.ExpiresAt}); err != nil {
		return RegistrationGrant{}, err
	}
	if err = s.saveReplay(ctx, tx, p, "registration_grant.issue", result.ID, 201, keyHash, requestHash, result, &result.ExpiresAt); err != nil {
		return RegistrationGrant{}, err
	}
	if err = commit(ctx, tx); err != nil {
		return RegistrationGrant{}, err
	}
	return result, nil
}
