//go:build integration

package authorization

import (
	"crypto/sha256"
	"strings"
	"sync"
	"testing"
	"time"
)

func (f fixture) credential(t *testing.T, peer int) string {
	t.Helper()
	token := "dev_" + strings.Repeat(string(rune('a'+peer)), 43)
	hash := sha256.Sum256([]byte(token))
	f.exec(t, `INSERT INTO device_credentials(tenant_id,device_id,credential_hash,expires_at)
VALUES($1,$2,$3,clock_timestamp()+interval '1 hour')`, f.peers[peer].TenantID, f.peers[peer].ID, hash[:])
	return token
}

func TestRecoveryGenerationCASAndFencing(t *testing.T) {
	f := setup(t)
	f.grant(t, 0, 1, "terminate", 4)
	value := f.request(t, 700)
	first, second := f.credential(t, 0), f.credential(t, 1)
	f.exec(t, "UPDATE sessions SET negotiation_started_at=clock_timestamp()-interval '2 seconds' WHERE id=$1", value.ID)
	// Existing accepted sessions remain valid after disabling new admissions.
	f.exec(t, "UPDATE devices SET connectable=false WHERE id=$1", f.peers[1].ID)
	var results [2]Session
	var failures [2]error
	var group sync.WaitGroup
	for i, token := range []string{first, second} {
		group.Add(1)
		go func(i int, token string) {
			defer group.Done()
			results[i], failures[i] = f.service.RecoverGeneration(f.ctx, f.peers[i], value.ID, token, 1)
		}(i, token)
	}
	group.Wait()
	for i := range results {
		if failures[i] != nil || results[i].NegotiationGeneration != 2 {
			t.Fatalf("CAS recovery failed: %v", failures[i])
		}
		if !results[i].SourceLeaseExpiresAt.Equal(value.SourceLeaseExpiresAt) || !results[i].TargetLeaseExpiresAt.Equal(value.TargetLeaseExpiresAt) {
			t.Fatal("recovery must not renew either lease")
		}
	}
	_, err := f.service.AuthorizeDescriptionGeneration(f.ctx, f.peers[0], value.ID, "session.offer", 1)
	code(t, err, "NEGOTIATION_STALE")
	_, err = f.service.MarkConnectedGeneration(f.ctx, f.peers[0], value.ID, 1)
	code(t, err, "NEGOTIATION_STALE")
	_, err = f.service.AuthorizeDescriptionGeneration(f.ctx, f.peers[1], value.ID, "session.offer", 2)
	code(t, err, "SIGNAL_ROLE_FORBIDDEN")
	_, err = f.service.AuthorizeDescriptionGeneration(f.ctx, f.peers[0], value.ID, "session.offer", 2)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.service.AuthorizeDescriptionGeneration(f.ctx, f.peers[1], value.ID, "session.answer", 2)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.service.RecoverGeneration(f.ctx, f.peers[0], value.ID, first, 2)
	code(t, err, "NEGOTIATION_RATE_LIMIT")
	f.exec(t, "UPDATE sessions SET negotiation_generation=32 WHERE id=$1", value.ID)
	_, err = f.service.RecoverGeneration(f.ctx, f.peers[0], value.ID, first, 32)
	code(t, err, "NEGOTIATION_LIMIT")
}

func TestRecoveryNeverRevivesOrBypassesAuthentication(t *testing.T) {
	f := setup(t)
	f.grant(t, 0, 1, "terminate", 4)
	value := f.request(t, 701)
	token := f.credential(t, 0)
	f.exec(t, "UPDATE sessions SET negotiation_started_at=clock_timestamp()-interval '2 seconds' WHERE id=$1", value.ID)
	f.exec(t, "UPDATE device_credentials SET revoked_at=clock_timestamp() WHERE device_id=$1", f.peers[0].ID)
	if _, err := f.service.RecoverGeneration(f.ctx, f.peers[0], value.ID, token, 1); err == nil {
		t.Fatal("revoked actual bearer recovered session")
	}
	current, err := f.service.Get(f.ctx, f.peers[0], value.ID)
	if err != nil || current.NegotiationGeneration != 1 {
		t.Fatal("denied recovery mutated generation")
	}
	_, err = f.service.RecoverGeneration(f.ctx, f.peers[3], value.ID, token, 1)
	code(t, err, "SESSION_NOT_FOUND")
	_, err = f.service.Respond(f.ctx, f.peers[1], value.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.service.RecoverGeneration(f.ctx, f.peers[0], value.ID, token, 1)
	code(t, err, "SESSION_CLOSED")
}

func TestRecoveryReplayRechecksLeaseAfterCredentialLock(t *testing.T) {
	f := setup(t)
	f.grant(t, 0, 1, "terminate", 4)
	value := f.request(t, 702)
	token := f.credential(t, 0)
	// Model a completed CAS whose idempotent retry is now waiting on credential work.
	var deadline time.Time
	if err := f.pool.QueryRow(f.ctx, `UPDATE sessions SET negotiation_generation=2,
 source_lease_expires_at=clock_timestamp()+interval '2 seconds',
 target_lease_expires_at=clock_timestamp()+interval '2 seconds'
 WHERE id=$1 RETURNING LEAST(source_lease_expires_at,target_lease_expires_at)`, value.ID).Scan(&deadline); err != nil {
		t.Fatal(err)
	}
	blocker, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(f.ctx)
	var blockerPID int
	if err = blocker.QueryRow(f.ctx, "SELECT pg_backend_pid()").Scan(&blockerPID); err != nil {
		t.Fatal(err)
	}
	if _, err = blocker.Exec(f.ctx, "SELECT id FROM device_credentials WHERE device_id=$1 FOR UPDATE", f.peers[0].ID); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, err := f.service.RecoverGeneration(f.ctx, f.peers[0], value.ID, token, 1); result <- err }()
	// Prove the retry reached the credential lock while the lease was still live.
	waitUntil := time.Now().Add(time.Second)
	for {
		var waiting bool
		if err = f.pool.QueryRow(f.ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))", blockerPID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(waitUntil) {
			t.Fatal("recovery did not reach the credential lock barrier")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err = f.pool.Exec(f.ctx, "SELECT pg_sleep(GREATEST(0,EXTRACT(EPOCH FROM ($1::timestamptz-clock_timestamp())))+0.05)", deadline); err != nil {
		t.Fatal(err)
	}
	if err = blocker.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		code(t, err, "LEASE_EXPIRED")
	case <-time.After(3 * time.Second):
		t.Fatal("blocked recovery did not finish")
	}
	var generation int
	if err = f.pool.QueryRow(f.ctx, "SELECT negotiation_generation FROM sessions WHERE id=$1", value.ID).Scan(&generation); err != nil || generation != 2 {
		t.Fatal("denied replay changed generation")
	}
}
