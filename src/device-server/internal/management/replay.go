package management

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

func validKey(key string) bool {
	if len(key) < 8 || len(key) > 128 {
		return false
	}
	for _, r := range key {
		if r < 33 || r > 126 {
			return false
		}
	}
	return true
}

func aad(p Principal, operation string, keyHash, requestHash []byte) []byte {
	domain := "peerloom-management-replay-v1"
	if p.browser != nil {
		domain = "peerloom-browser-management-replay-v1"
	}
	value, _ := json.Marshal([]any{domain, p.tenantID, p.credentialID, operation, keyHash, requestHash})
	return value
}

// prepareReplay serializes one semantic mutation key in PostgreSQL. Authority
// is revalidated by begin before any old response can be decrypted.
func (s *Service) prepareReplay(ctx context.Context, tx pgx.Tx, p Principal, operation, key string, input any, output any) (bool, []byte, []byte, error) {
	if !validKey(key) {
		return false, nil, nil, fail("IDEMPOTENCY_KEY_REQUIRED", 422)
	}
	canonical, err := json.Marshal(input)
	if err != nil {
		return false, nil, nil, fail("INVALID_INPUT", 422)
	}
	keyHash, requestHash := hash(key), hash(string(canonical))
	lockHash := hash(string(aad(p, operation, keyHash, nil)))
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", int64(binary.BigEndian.Uint64(lockHash[:8]))); err != nil {
		return false, nil, nil, fail("DATABASE_UNAVAILABLE", 503)
	}
	var storedHash, nonce, ciphertext []byte
	var expired bool
	table, column := p.replayTable()
	err = tx.QueryRow(ctx, `SELECT request_hash,response_nonce,response_ciphertext,response_expires_at<=clock_timestamp()
FROM `+table+` WHERE tenant_id=$1 AND `+column+`=$2 AND operation=$3 AND key_hash=$4`, p.tenantID, p.credentialID, operation, keyHash).Scan(&storedHash, &nonce, &ciphertext, &expired)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, keyHash, requestHash, nil
	}
	if err != nil {
		return false, nil, nil, fail("DATABASE_UNAVAILABLE", 503)
	}
	if subtle.ConstantTimeCompare(storedHash, requestHash) != 1 {
		return false, nil, nil, fail("IDEMPOTENCY_CONFLICT", 409)
	}
	if expired || len(ciphertext) == 0 {
		return false, nil, nil, fail("REPLAY_EXPIRED", 409)
	}
	if len(nonce) != s.aead.NonceSize() {
		return false, nil, nil, fail("REPLAY_UNAVAILABLE", 503)
	}
	plain, err := s.aead.Open(nil, nonce, ciphertext, aad(p, operation, keyHash, requestHash))
	if err != nil {
		return false, nil, nil, fail("REPLAY_UNAVAILABLE", 503)
	}
	if err = json.Unmarshal(plain, output); err != nil {
		return false, nil, nil, fail("REPLAY_UNAVAILABLE", 503)
	}
	return true, keyHash, requestHash, nil
}

func (s *Service) saveReplay(ctx context.Context, tx pgx.Tx, p Principal, operation, resourceID string, status int, keyHash, requestHash []byte, result any, secretDeadline *time.Time) error {
	var at time.Time
	if err := tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&at); err != nil {
		return fail("DATABASE_UNAVAILABLE", 503)
	}
	responseUntil := at.Add(s.settings.ResponseTTL)
	if secretDeadline != nil && secretDeadline.Before(responseUntil) {
		responseUntil = *secretDeadline
	}
	plain, err := json.Marshal(result)
	if err != nil {
		return fail("INTERNAL_ERROR", 500)
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return fail("INTERNAL_ERROR", 500)
	}
	ciphertext := s.aead.Seal(nil, nonce, plain, aad(p, operation, keyHash, requestHash))
	table, column := p.replayTable()
	_, err = tx.Exec(ctx, `INSERT INTO `+table+`(tenant_id,`+column+`,operation,key_hash,request_hash,status_code,resource_id,response_nonce,response_ciphertext,response_expires_at,expires_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, p.tenantID, p.credentialID, operation, keyHash, requestHash, status, resourceID, nonce, ciphertext, responseUntil, at.Add(s.settings.ReceiptTTL))
	if err != nil {
		return fail("DATABASE_UNAVAILABLE", 503)
	}
	return nil
}

// PurgeExpired first removes old ciphertext while retaining a tombstone. The
// documented idempotency guarantee ends when the receipt retention window ends.
func (s *Service) PurgeExpired(ctx context.Context) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fail("DATABASE_UNAVAILABLE", 503)
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, "UPDATE management_requests SET response_nonce=NULL,response_ciphertext=NULL WHERE response_expires_at<=clock_timestamp() AND response_ciphertext IS NOT NULL"); err != nil {
		return fail("DATABASE_UNAVAILABLE", 503)
	}
	if _, err = tx.Exec(ctx, "DELETE FROM management_requests WHERE expires_at<=clock_timestamp()"); err != nil {
		return fail("DATABASE_UNAVAILABLE", 503)
	}
	return commit(ctx, tx)
}
