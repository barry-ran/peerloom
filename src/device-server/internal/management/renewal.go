package management

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Renewal policy is deliberately server-owned, never selected by a client.
const serviceKeyLifetime = 30 * 24 * time.Hour
const serviceKeyRenewWindow = 7 * 24 * time.Hour
const serviceKeyOverlap = 24 * time.Hour

type ServiceKeySelf struct {
	SubjectID            string    `json:"subject_id"`
	TenantID             string    `json:"tenant_id"`
	CredentialID         string    `json:"credential_id"`
	Scope                Scope     `json:"scope"`
	ExpiresAt            time.Time `json:"expires_at"`
	RenewAfter           time.Time `json:"renew_after"`
	EffectiveAcceptUntil time.Time `json:"effective_accept_until"`
}
type ServiceKeyRenewal struct {
	ServiceKeySelf
	ServiceCredential    string    `json:"service_credential"`
	PreviousCredentialID string    `json:"previous_credential_id"`
	PreviousAcceptUntil  time.Time `json:"previous_accept_until"`
}

func keySelf(ctx context.Context, tx pgx.Tx, p Principal) (ServiceKeySelf, error) {
	r := ServiceKeySelf{SubjectID: p.subjectID, TenantID: p.tenantID, CredentialID: p.credentialID, Scope: p.scope}
	err := tx.QueryRow(ctx, `SELECT expires_at,LEAST(expires_at,COALESCE(accept_until,expires_at)) FROM tenant_service_credentials WHERE id=$1`, p.credentialID).Scan(&r.ExpiresAt, &r.EffectiveAcceptUntil)
	r.RenewAfter = r.ExpiresAt.Add(-serviceKeyRenewWindow)
	return r, err
}
func (s *Service) ServiceKeySelf(ctx context.Context, p Principal) (ServiceKeySelf, error) {
	if p.browser != nil {
		return ServiceKeySelf{}, fail("SERVICE_AUTH_REQUIRED", 403)
	}
	tx, err := s.begin(ctx, p, false)
	if err != nil {
		return ServiceKeySelf{}, err
	}
	defer rollback(tx)
	r, err := keySelf(ctx, tx, p)
	if err != nil {
		return r, fail("DATABASE_UNAVAILABLE", 503)
	}
	return r, commit(ctx, tx)
}
func renewalAAD(subject, previous, next string) []byte {
	b, _ := json.Marshal([]string{"peerloom-service-renewal-v1", subject, previous, next})
	return b
}
func (s *Service) RenewServiceKey(ctx context.Context, p Principal, operation string) (ServiceKeyRenewal, error) {
	return s.RenewServiceKeyPersisted(ctx, p, operation, nil)
}

// persist is used only by the trusted offline CLI. It must durably store the
// result before commit. HTTP clients journal the operation before making a call.
func (s *Service) RenewServiceKeyPersisted(ctx context.Context, p Principal, operation string, persist func(ServiceKeyRenewal) error) (ServiceKeyRenewal, error) {
	var r ServiceKeyRenewal
	if p.browser != nil {
		return r, fail("SERVICE_AUTH_REQUIRED", 403)
	}
	if len(operation) < 32 || !validKey(operation) {
		return r, fail("IDEMPOTENCY_KEY_REQUIRED", 422)
	}
	tx, err := s.beginAuthority(ctx, p, false, true)
	if err != nil {
		return r, err
	}
	defer rollback(tx)
	var current string
	if err = tx.QueryRow(ctx, "SELECT current_credential_id::text FROM service_subjects WHERE id=$1", p.subjectID).Scan(&current); err != nil {
		return r, fail("DATABASE_UNAVAILABLE", 503)
	}
	var next string
	var opHash, nonce, ciphertext []byte
	var until time.Time
	err = tx.QueryRow(ctx, `SELECT next_credential_id::text,operation_hash,response_nonce,response_ciphertext,replay_until FROM service_key_renewals WHERE previous_credential_id=$1`, p.credentialID).Scan(&next, &opHash, &nonce, &ciphertext, &until)
	if err == nil {
		if subtle.ConstantTimeCompare(opHash, hash(operation)) != 1 {
			return r, fail("RENEWAL_ALREADY_EXISTS", 409)
		}
		var usable bool
		if err = tx.QueryRow(ctx, `SELECT $2>clock_timestamp() AND EXISTS(SELECT 1 FROM tenant_service_credentials WHERE id=$1 AND revoked_at IS NULL AND expires_at>clock_timestamp() AND (accept_until IS NULL OR accept_until>clock_timestamp()))`, next, until).Scan(&usable); err != nil {
			return r, fail("DATABASE_UNAVAILABLE", 503)
		}
		if !usable || len(nonce) != s.aead.NonceSize() || len(ciphertext) == 0 {
			return r, fail("RENEWAL_UNAVAILABLE", 409)
		}
		plain, err := s.aead.Open(nil, nonce, ciphertext, renewalAAD(p.subjectID, p.credentialID, next))
		if err != nil {
			return r, fail("RENEWAL_UNAVAILABLE", 409)
		}
		if err = json.Unmarshal(plain, &r); err != nil {
			return r, fail("RENEWAL_UNAVAILABLE", 409)
		}
		if persist != nil {
			if err = persist(r); err != nil {
				return r, err
			}
		}
		return r, commit(ctx, tx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return r, fail("DATABASE_UNAVAILABLE", 503)
	}
	if current != p.credentialID {
		return r, fail("RENEWAL_UNAVAILABLE", 409)
	}
	self, err := keySelf(ctx, tx, p)
	if err != nil {
		return r, fail("DATABASE_UNAVAILABLE", 503)
	}
	var now time.Time
	if err = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return r, fail("DATABASE_UNAVAILABLE", 503)
	}
	if now.Before(self.RenewAfter) {
		return r, fail("RENEWAL_TOO_EARLY", 409)
	}
	secret, err := token("svc_")
	if err != nil {
		return r, err
	}
	until = now.Add(serviceKeyOverlap)
	if self.EffectiveAcceptUntil.Before(until) {
		until = self.EffectiveAcceptUntil
	}
	expiry := now.Add(serviceKeyLifetime)
	r = ServiceKeyRenewal{ServiceKeySelf: ServiceKeySelf{SubjectID: p.subjectID, TenantID: p.tenantID, Scope: self.Scope, ExpiresAt: expiry, RenewAfter: expiry.Add(-serviceKeyRenewWindow), EffectiveAcceptUntil: expiry}, ServiceCredential: secret, PreviousCredentialID: p.credentialID, PreviousAcceptUntil: until}
	err = tx.QueryRow(ctx, `INSERT INTO tenant_service_credentials(tenant_id,subject_id,credential_hash,scope,label,expires_at) VALUES($1,$2,$3,$4,'automatic-renewal',$5) RETURNING id::text`, p.tenantID, p.subjectID, hash(secret), self.Scope, expiry).Scan(&r.CredentialID)
	if err != nil {
		return r, fail("DATABASE_UNAVAILABLE", 503)
	}
	if _, err = tx.Exec(ctx, "UPDATE tenant_service_credentials SET accept_until=$2 WHERE id=$1", p.credentialID, until); err != nil {
		return r, fail("DATABASE_UNAVAILABLE", 503)
	}
	if _, err = tx.Exec(ctx, "UPDATE service_subjects SET current_credential_id=$2 WHERE id=$1", p.subjectID, r.CredentialID); err != nil {
		return r, fail("DATABASE_UNAVAILABLE", 503)
	}
	plain, err := json.Marshal(r)
	if err != nil {
		return r, err
	}
	nonce = make([]byte, s.aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return r, err
	}
	ciphertext = s.aead.Seal(nil, nonce, plain, renewalAAD(p.subjectID, p.credentialID, r.CredentialID))
	if _, err = tx.Exec(ctx, `INSERT INTO service_key_renewals(previous_credential_id,next_credential_id,subject_id,operation_hash,response_nonce,response_ciphertext,replay_until) VALUES($1,$2,$3,$4,$5,$6,$7)`, p.credentialID, r.CredentialID, p.subjectID, hash(operation), nonce, ciphertext, until); err != nil {
		return r, fail("DATABASE_UNAVAILABLE", 503)
	}
	if err = recordAudit(ctx, tx, p.tenantID, "service_credential", p.credentialID, "service_key.renew", "service_credential", r.CredentialID, map[string]any{"subject_id": p.subjectID}); err != nil {
		return r, err
	}
	if persist != nil {
		if err = persist(r); err != nil {
			return r, err
		}
	}
	if err = commit(ctx, tx); err != nil {
		return r, &CommitUncertainError{Err: err}
	}
	return r, nil
}
