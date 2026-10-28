package identity

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool     *pgxpool.Pool
	aead     cipher.AEAD
	settings Settings
}

func New(pool *pgxpool.Pool, key []byte) (*Store, error) {
	return NewWithSettings(pool, key, DefaultSettings())
}

func NewWithSettings(pool *pgxpool.Pool, key []byte, settings Settings) (*Store, error) {
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return &Store{pool: pool, aead: aead, settings: settings}, nil
}

func validIdempotency(key string) bool {
	if len(key) < 8 || len(key) > 128 {
		return false
	}
	for _, c := range key {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}

func rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}

func (s *Store) Register(ctx context.Context, input Registration, idempotencyKey string) (Credential, error) {
	if err := input.Validate(); err != nil {
		return Credential{}, err
	}
	if !validIdempotency(idempotencyKey) {
		return Credential{}, Fail("IDEMPOTENCY_KEY_REQUIRED", 422)
	}
	if !strings.HasPrefix(input.RegistrationGrant, "reg_") {
		return Credential{}, Fail("GRANT_INVALID", 403)
	}
	canonical, err := json.Marshal(input)
	if err != nil {
		return Credential{}, Fail("INVALID_INPUT", 422)
	}
	requestHash, keyHash := digest(string(canonical)), digest(idempotencyKey)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Credential{}, Fail("DATABASE_UNAVAILABLE", 503)
	}
	defer rollback(tx)
	var tenant, mode string
	var enabled bool
	err = tx.QueryRow(ctx, `SELECT a.tenant_id::text,a.registration_mode,a.enabled AND t.status='active'
FROM applications a JOIN tenants t ON t.id=a.tenant_id WHERE a.id=$1 FOR SHARE OF a,t`, input.ApplicationID).Scan(&tenant, &mode, &enabled)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !enabled {
		return Credential{}, Fail("GRANT_INVALID", 403)
	}
	if err != nil {
		return Credential{}, Fail("DATABASE_UNAVAILABLE", 503)
	}
	if mode != "grant" && mode != "both" {
		return Credential{}, Fail("GRANT_REGISTRATION_DISABLED", 403)
	}
	var grantID string
	var expires time.Time
	var consumed *time.Time
	err = tx.QueryRow(ctx, `SELECT id::text,expires_at,consumed_at FROM registration_grants
WHERE tenant_id=$1 AND application_id=$2 AND secret_hash=$3 FOR UPDATE`, tenant, input.ApplicationID, digest(input.RegistrationGrant)).Scan(&grantID, &expires, &consumed)
	if errors.Is(err, pgx.ErrNoRows) {
		return Credential{}, Fail("GRANT_INVALID", 403)
	}
	if err != nil {
		return Credential{}, Fail("DATABASE_UNAVAILABLE", 503)
	}
	var now time.Time
	if err = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return Credential{}, Fail("DATABASE_UNAVAILABLE", 503)
	}
	if !expires.After(now) {
		return Credential{}, Fail("GRANT_EXPIRED", 403)
	}
	scope := input.ApplicationID + ":" + hex.EncodeToString(digest(input.RegistrationGrant))
	result, found, err := s.loadReplay(ctx, tx, tenant, "registration", scope, keyHash, requestHash)
	if err != nil {
		return Credential{}, err
	}
	if found {
		return result, nil
	}
	if consumed != nil {
		return Credential{}, Fail("GRANT_CONSUMED", 409)
	}
	metadata := input.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadataJSON, _ := json.Marshal(metadata)
	var deviceID string
	err = tx.QueryRow(ctx, `INSERT INTO devices(tenant_id,application_id,installation_key_hash,platform,sdk_version,metadata)
VALUES($1,$2,$3,$4,$5,$6) RETURNING id::text`, tenant, input.ApplicationID, digest(input.InstallationPublicKey), input.Platform, input.SDKVersion, metadataJSON).Scan(&deviceID)
	if err != nil {
		return Credential{}, Fail("DATABASE_UNAVAILABLE", 503)
	}
	result, err = s.issue(ctx, tx, tenant, deviceID, now)
	if err != nil {
		return Credential{}, err
	}
	if _, err = tx.Exec(ctx, "UPDATE registration_grants SET consumed_at=$1 WHERE id=$2", now, grantID); err != nil {
		return Credential{}, Fail("DATABASE_UNAVAILABLE", 503)
	}
	replayUntil := now.Add(s.settings.ReplayTTL)
	if expires.Before(replayUntil) {
		replayUntil = expires
	}
	if err = s.saveReplay(ctx, tx, tenant, "registration", scope, keyHash, requestHash, result, replayUntil); err != nil {
		return Credential{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Credential{}, Fail("COMMIT_UNCERTAIN_RETRY_SAME_KEY", 503)
	}
	return result, nil
}

func (s *Store) issue(ctx context.Context, tx pgx.Tx, tenant, deviceID string, now time.Time) (Credential, error) {
	token, err := randomToken("dev_")
	if err != nil {
		return Credential{}, Fail("INTERNAL_ERROR", 500)
	}
	expires := now.Add(s.settings.CredentialTTL)
	if _, err = tx.Exec(ctx, `INSERT INTO device_credentials(tenant_id,device_id,credential_hash,expires_at) VALUES($1,$2,$3,$4)`, tenant, deviceID, digest(token), expires); err != nil {
		return Credential{}, Fail("DATABASE_UNAVAILABLE", 503)
	}
	return Credential{DeviceID: deviceID, DeviceCredential: token, ExpiresAt: expires.UTC().Format(time.RFC3339Nano)}, nil
}

type queryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func authenticate(ctx context.Context, db queryer, token string) (Device, error) {
	if !strings.HasPrefix(token, "dev_") || len(token) != 47 {
		return Device{}, Fail("AUTH_INVALID", 401)
	}
	var result Device
	err := db.QueryRow(ctx, `SELECT d.id::text,d.tenant_id::text,d.application_id::text,d.platform,d.metadata
FROM device_credentials c JOIN devices d ON d.id=c.device_id AND d.tenant_id=c.tenant_id
JOIN applications a ON a.id=d.application_id AND a.tenant_id=d.tenant_id JOIN tenants t ON t.id=d.tenant_id
WHERE c.credential_hash=$1 AND c.revoked_at IS NULL AND c.expires_at>clock_timestamp()
AND d.status='active' AND a.enabled AND t.status='active'`, digest(token)).Scan(&result.ID, &result.TenantID, &result.ApplicationID, &result.Platform, &result.Metadata)
	if errors.Is(err, pgx.ErrNoRows) {
		return Device{}, Fail("AUTH_INVALID", 401)
	}
	if err != nil {
		return Device{}, Fail("DATABASE_UNAVAILABLE", 503)
	}
	return result, nil
}

func (s *Store) Authenticate(ctx context.Context, token string) (Device, error) {
	return authenticate(ctx, s.pool, token)
}

func (s *Store) Refresh(ctx context.Context, token, idempotencyKey string) (Credential, error) {
	if !validIdempotency(idempotencyKey) {
		return Credential{}, Fail("IDEMPOTENCY_KEY_REQUIRED", 422)
	}
	device, err := s.Authenticate(ctx, token)
	if err != nil {
		return Credential{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Credential{}, Fail("DATABASE_UNAVAILABLE", 503)
	}
	defer rollback(tx)
	// Match registration's lock order: application/tenant, device, credential.
	// Configuration changes and credential revocation cannot race the final check.
	var enabled bool
	if err = tx.QueryRow(ctx, `SELECT a.enabled AND t.status='active' FROM applications a
JOIN tenants t ON t.id=a.tenant_id WHERE a.id=$1 AND a.tenant_id=$2 FOR SHARE OF a,t`, device.ApplicationID, device.TenantID).Scan(&enabled); err != nil {
		return Credential{}, Fail("DATABASE_UNAVAILABLE", 503)
	}
	if !enabled {
		return Credential{}, Fail("AUTH_INVALID", 401)
	}
	var status string
	if err = tx.QueryRow(ctx, "SELECT status FROM devices WHERE id=$1 AND tenant_id=$2 FOR UPDATE", device.ID, device.TenantID).Scan(&status); err != nil {
		return Credential{}, Fail("DATABASE_UNAVAILABLE", 503)
	}
	if status != "active" {
		return Credential{}, Fail("AUTH_INVALID", 401)
	}
	var credentialID string
	var rotated *time.Time
	if err = tx.QueryRow(ctx, "SELECT id::text,rotated_at FROM device_credentials WHERE tenant_id=$1 AND credential_hash=$2 FOR UPDATE", device.TenantID, digest(token)).Scan(&credentialID, &rotated); err != nil {
		return Credential{}, Fail("AUTH_INVALID", 401)
	}
	if _, err = authenticate(ctx, tx, token); err != nil {
		return Credential{}, err
	}
	scope := device.ID + ":" + hex.EncodeToString(digest(token))
	keyHash, requestHash := digest(idempotencyKey), digest("refresh:"+token)
	result, found, err := s.loadReplay(ctx, tx, device.TenantID, "refresh", scope, keyHash, requestHash)
	if err != nil {
		return Credential{}, err
	}
	if found {
		return result, nil
	}
	if rotated != nil {
		return Credential{}, Fail("CREDENTIAL_ALREADY_ROTATED", 409)
	}
	var now time.Time
	if err = tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return Credential{}, Fail("DATABASE_UNAVAILABLE", 503)
	}
	result, err = s.issue(ctx, tx, device.TenantID, device.ID, now)
	if err != nil {
		return Credential{}, err
	}
	if _, err = tx.Exec(ctx, "UPDATE device_credentials SET expires_at=LEAST(expires_at,$1),rotated_at=$2 WHERE id=$3", now.Add(s.settings.RotationOverlap), now, credentialID); err != nil {
		return Credential{}, Fail("DATABASE_UNAVAILABLE", 503)
	}
	if err = s.saveReplay(ctx, tx, device.TenantID, "refresh", scope, keyHash, requestHash, result, now.Add(min(s.settings.RotationOverlap, s.settings.ReplayTTL))); err != nil {
		return Credential{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Credential{}, Fail("COMMIT_UNCERTAIN_RETRY_SAME_KEY", 503)
	}
	return result, nil
}

func (s *Store) loadReplay(ctx context.Context, tx pgx.Tx, tenant, operation, scope string, keyHash, requestHash []byte) (Credential, bool, error) {
	var storedHash, nonce, ciphertext []byte
	var expired bool
	err := tx.QueryRow(ctx, `SELECT request_hash,nonce,ciphertext,expires_at<=clock_timestamp() FROM identity_replays
WHERE tenant_id=$1 AND operation=$2 AND principal_scope=$3 AND key_hash=$4`, tenant, operation, scope, keyHash).Scan(&storedHash, &nonce, &ciphertext, &expired)
	if errors.Is(err, pgx.ErrNoRows) {
		return Credential{}, false, nil
	}
	if err != nil {
		return Credential{}, false, Fail("DATABASE_UNAVAILABLE", 503)
	}
	if subtle.ConstantTimeCompare(storedHash, requestHash) != 1 {
		return Credential{}, false, Fail("IDEMPOTENCY_CONFLICT", 409)
	}
	if expired {
		return Credential{}, false, Fail("REPLAY_EXPIRED", 409)
	}
	if len(nonce) != s.aead.NonceSize() {
		return Credential{}, false, Fail("REPLAY_UNAVAILABLE", 503)
	}
	plain, err := s.aead.Open(nil, nonce, ciphertext, replayAAD(operation, tenant+":"+scope, keyHash, requestHash))
	if err != nil {
		return Credential{}, false, Fail("REPLAY_UNAVAILABLE", 503)
	}
	var result Credential
	if err = json.Unmarshal(plain, &result); err != nil {
		return Credential{}, false, Fail("REPLAY_UNAVAILABLE", 503)
	}
	// A replay must never resurrect a revoked/expired device credential.
	device, err := authenticate(ctx, tx, result.DeviceCredential)
	if err != nil {
		return Credential{}, false, err
	}
	if device.TenantID != tenant || device.ID != result.DeviceID {
		return Credential{}, false, Fail("REPLAY_UNAVAILABLE", 503)
	}
	// Rotation can shorten a previously issued credential's lifetime. Preserve
	// identity/token idempotency but never advertise the stale original expiry.
	var effectiveExpiry time.Time
	if err = tx.QueryRow(ctx, "SELECT expires_at FROM device_credentials WHERE tenant_id=$1 AND credential_hash=$2", tenant, digest(result.DeviceCredential)).Scan(&effectiveExpiry); err != nil {
		return Credential{}, false, Fail("REPLAY_UNAVAILABLE", 503)
	}
	result.ExpiresAt = effectiveExpiry.UTC().Format(time.RFC3339Nano)
	return result, true, nil
}

func (s *Store) saveReplay(ctx context.Context, tx pgx.Tx, tenant, operation, scope string, keyHash, requestHash []byte, result Credential, expires time.Time) error {
	plain, err := json.Marshal(result)
	if err != nil {
		return Fail("INTERNAL_ERROR", 500)
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return Fail("INTERNAL_ERROR", 500)
	}
	ciphertext := s.aead.Seal(nil, nonce, plain, replayAAD(operation, tenant+":"+scope, keyHash, requestHash))
	_, err = tx.Exec(ctx, `INSERT INTO identity_replays(tenant_id,operation,principal_scope,key_hash,request_hash,nonce,ciphertext,expires_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, tenant, operation, scope, keyHash, requestHash, nonce, ciphertext, expires)
	if err != nil {
		return Fail("DATABASE_UNAVAILABLE", 503)
	}
	return nil
}

// PurgeExpired removes replay ciphertext after its recovery window.
func (s *Store) PurgeExpired(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM identity_replays WHERE expires_at<=clock_timestamp()")
	if err != nil {
		return Fail("DATABASE_UNAVAILABLE", 503)
	}
	return nil
}
