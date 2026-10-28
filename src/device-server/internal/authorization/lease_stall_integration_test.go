//go:build integration

package authorization

import (
	"context"
	"testing"
	"time"
)

// Real default 60-second lease: one peer continuing renewal must not keep an
// unresponsive peer authorized. No timestamp UPDATE or shortened service TTL.
func TestActualDefaultLeaseStallDeniesRenewal(t *testing.T) {
	f := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	f.ctx = ctx
	f.grant(t, 0, 1, "terminate", 2)
	initial := f.request(t, 10001)
	if initial.State != "connecting" || initial.TargetLeaseExpiresAt.IsZero() {
		t.Fatal("expected a real accepted lease")
	}
	wait := time.Until(initial.TargetLeaseExpiresAt.Add(-5 * time.Second))
	if wait < 0 || wait > 65*time.Second {
		t.Fatal("unexpected actual default lease deadline")
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal("deadline wait cancelled")
	}
	source, err := f.service.Renew(ctx, f.peers[0], initial.ID)
	if err != nil || !source.TargetLeaseExpiresAt.Equal(initial.TargetLeaseExpiresAt) ||
		!source.SourceLeaseExpiresAt.After(initial.TargetLeaseExpiresAt) {
		t.Fatal("single-peer renewal changed the stalled peer deadline", err)
	}
	// Wait against the DB clock and the captured actual deadline, not an assumed
	// timer that might have started before target approval.
	if _, err = f.pool.Exec(ctx, "SELECT pg_sleep(GREATEST(0,EXTRACT(EPOCH FROM ($1::timestamptz-clock_timestamp())))+0.1)", initial.TargetLeaseExpiresAt); err != nil {
		t.Fatal(err)
	}
	var sourceStillFuture bool
	if err = f.pool.QueryRow(ctx, "SELECT source_lease_expires_at>clock_timestamp() FROM sessions WHERE id=$1", initial.ID).Scan(&sourceStillFuture); err != nil || !sourceStillFuture {
		t.Fatal("negative case must isolate stalled target, not expire both peers", err)
	}
	_, err = f.service.Renew(ctx, f.peers[0], initial.ID)
	code(t, err, "LEASE_EXPIRED")
	_, err = f.service.AuthorizeSignal(ctx, f.peers[0], initial.ID)
	code(t, err, "SESSION_CLOSED")
	t.Logf("actual target deadline crossed; only source renewed; lease generation %d -> %d; renewal and signaling denied", initial.LeaseGeneration, source.LeaseGeneration)
}
