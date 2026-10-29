package management

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"strings"

	"github.com/barry-ran/peerloom/src/device-server/internal/authorization"
	"github.com/jackc/pgx/v5"
)

type ExclusivePrepareInput struct {
	SourceDeviceID   string `json:"source_device_id"`
	TargetDeviceID   string `json:"target_device_id"`
	ExpiresInSeconds int    `json:"expires_in_seconds"`
}

// PrepareExclusiveSession is a trusted service operation, not a device bearer
// shortcut. A replay resolves its original row and cannot mint fresh authority.
func (s *Service) PrepareExclusiveSession(ctx context.Context, p Principal, input ExclusivePrepareInput, key string) (authorization.Session, error) {
	input.SourceDeviceID = strings.ToLower(input.SourceDeviceID)
	input.TargetDeviceID = strings.ToLower(input.TargetDeviceID)
	if !uuidPattern.MatchString(input.SourceDeviceID) || !uuidPattern.MatchString(input.TargetDeviceID) || input.SourceDeviceID == input.TargetDeviceID || input.ExpiresInSeconds < 1 || input.ExpiresInSeconds > 2592000 {
		return authorization.Session{}, fail("INVALID_INPUT", 422)
	}
	if !validKey(key) {
		return authorization.Session{}, fail("IDEMPOTENCY_KEY_REQUIRED", 422)
	}
	if p.browser != nil {
		return authorization.Session{}, fail("SERVICE_AUTH_REQUIRED", 403)
	}
	tx, err := s.begin(ctx, p, true)
	if err != nil {
		return authorization.Session{}, err
	}
	defer rollback(tx)
	encoded, _ := json.Marshal(input)
	kh, rh := hash(key), hash(string(encoded))
	var prior string
	var previousHash []byte
	err = tx.QueryRow(ctx, `SELECT session_id::text,request_hash FROM exclusive_prepare_requests WHERE tenant_id=$1 AND credential_id=$2 AND key_hash=$3`, p.tenantID, p.credentialID, kh).Scan(&prior, &previousHash)
	if err == nil {
		if subtle.ConstantTimeCompare(previousHash, rh) != 1 {
			return authorization.Session{}, fail("IDEMPOTENCY_CONFLICT", 409)
		}
		value, readErr := authorization.ReadExclusiveInTx(ctx, tx, p.tenantID, prior)
		if readErr != nil {
			return value, bridgeError(readErr)
		}
		if err = commit(ctx, tx); err != nil {
			return authorization.Session{}, err
		}
		return value, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return authorization.Session{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	// Presence is a fresh availability observation, never the ownership lock.
	if s.presence == nil {
		return authorization.Session{}, fail("PRESENCE_UNAVAILABLE", 503)
	}
	online, err := s.presence.Online(ctx, p.tenantID, input.TargetDeviceID)
	if err != nil {
		return authorization.Session{}, fail("PRESENCE_UNAVAILABLE", 503)
	}
	if !online {
		return authorization.Session{}, fail("TARGET_OFFLINE", 409)
	}
	result, err := authorization.PrepareExclusiveInTx(ctx, tx, p.tenantID, input.SourceDeviceID, input.TargetDeviceID, input.ExpiresInSeconds)
	if err != nil {
		return authorization.Session{}, bridgeError(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO exclusive_prepare_requests(tenant_id,credential_id,key_hash,request_hash,session_id) VALUES($1,$2,$3,$4,$5)`, p.tenantID, p.credentialID, kh, rh, result.ID); err != nil {
		return authorization.Session{}, fail("DATABASE_UNAVAILABLE", 503)
	}
	if err = recordAudit(ctx, tx, p.tenantID, p.actorType(), p.credentialID, "exclusive_session.prepare", "session", result.ID, map[string]any{"target_epoch": result.TargetEpoch}); err != nil {
		return authorization.Session{}, err
	}
	if err = commit(ctx, tx); err != nil {
		return authorization.Session{}, err
	}
	return result, nil
}
