//go:build integration

package authorization

import (
	"context"
	"sync"
	"testing"
	"time"
)

func (f fixture) prepareExclusive(t *testing.T, source, target int) (Session, error) {
	t.Helper()
	tx, err := f.service.begin(f.ctx, f.peers[source].TenantID)
	if err != nil {
		return Session{}, err
	}
	defer rollback(tx)
	value, err := PrepareExclusiveInTx(f.ctx, tx, f.peers[source].TenantID, f.peers[source].ID, f.peers[target].ID, 3600)
	if err == nil {
		err = commit(f.ctx, tx)
	}
	return value, err
}
func exclusiveContext(ctx context.Context, epoch, fence string) context.Context {
	return WithExclusiveFenceCheck(WithExclusiveAuthority(ctx, epoch, fence), func(context.Context) error { return nil })
}
func TestExclusiveCompetitionEpochFenceAndHistoricalACK(t *testing.T) {
	f := setup(t)
	f.exec(t, `UPDATE applications SET exclusive_target=true WHERE id=$1`, f.peers[1].ApplicationID)
	results := make(chan Session, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, source := range []int{0, 2} {
		wg.Add(1)
		go func(source int) {
			defer wg.Done()
			value, err := f.prepareExclusive(t, source, 1)
			if err != nil {
				errs <- err
			} else {
				results <- value
			}
		}(source)
	}
	wg.Wait()
	close(results)
	close(errs)
	if len(results) != 1 || len(errs) != 1 {
		t.Fatalf("competition wins=%d failures=%d", len(results), len(errs))
	}
	code(t, <-errs, "TARGET_OCCUPIED")
	value := <-results
	source := f.peers[0]
	other := 2
	if value.SourceDeviceID == f.peers[2].ID {
		source = f.peers[2]
		other = 0
	}
	if value.TargetEpoch != "1" || !value.Prepared || value.ExclusiveReleaseState != "held" {
		t.Fatal("invalid preparation shape")
	}
	_, err := f.service.Respond(f.ctx, f.peers[1], value.ID, true)
	code(t, err, "EXCLUSIVE_EPOCH_STALE")
	ctx := exclusiveContext(f.ctx, value.TargetEpoch, "first-runtime")
	_, err = f.service.Respond(ctx, f.peers[1], value.ID, true)
	code(t, err, "EXCLUSIVE_PREPARE_REQUIRED")
	value, err = f.service.ConnectPrepared(ctx, source, value.ID)
	if err != nil || value.Prepared {
		t.Fatalf("connect prepared: %v", err)
	}
	value, err = f.service.Respond(ctx, f.peers[1], value.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	oldWater := *value.ReleaseNotBefore
	value, err = f.service.Renew(ctx, f.peers[1], value.ID)
	if err != nil || value.ReleaseNotBefore.Before(oldWater) {
		t.Fatalf("watermark regression: %v", err)
	}
	_, err = f.service.Renew(exclusiveContext(f.ctx, "2", "first-runtime"), source, value.ID)
	code(t, err, "EXCLUSIVE_EPOCH_STALE")
	// Both WSS and HTTP ICE lack-epoch cannot use the old compatibility path.
	tx, err := f.service.begin(f.ctx, source.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.service.AuthorizeICEInTx(f.ctx, tx, source, value.ID)
	rollback(tx)
	code(t, err, "EXCLUSIVE_EPOCH_STALE")
	value, err = f.service.Close(ctx, source, value.ID, "CLIENT_CLOSED")
	if err != nil || value.ExclusiveReleaseState != "closing" {
		t.Fatalf("source close: %v", err)
	}
	_, err = f.prepareExclusive(t, other, 1)
	code(t, err, "TARGET_OCCUPIED")
	// Turning policy off must not bypass an occupied resource.
	f.exec(t, `UPDATE applications SET exclusive_target=false WHERE id=$1`, f.peers[1].ApplicationID)
	_, err = f.service.Request(f.ctx, f.peers[other], f.peers[1].ID, requestID(901))
	code(t, err, "TARGET_OCCUPIED")
	f.exec(t, `UPDATE applications SET exclusive_target=true WHERE id=$1`, f.peers[1].ApplicationID)
	_, err = f.service.FenceAck(exclusiveContext(f.ctx, "1", "new-runtime"), f.peers[1], value.ID, "1")
	code(t, err, "EXCLUSIVE_FENCE_STALE")
	_, err = f.service.FenceAck(ctx, source, value.ID, "1")
	code(t, err, "TARGET_ONLY")
	fenced, err := f.service.FenceAck(ctx, f.peers[1], value.ID, "1")
	if err != nil || !fenced.TargetFenced || fenced.ExclusiveReleaseState != "released" {
		t.Fatalf("fence: %v", err)
	}
	next, err := f.prepareExclusive(t, other, 1)
	if err != nil || next.TargetEpoch != "2" {
		t.Fatalf("next epoch: %v", err)
	}
	// Historical ACK remains idempotent but may not release epoch two.
	_, err = f.service.FenceAck(ctx, f.peers[1], value.ID, "1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.prepareExclusive(t, other, 1)
	code(t, err, "TARGET_OCCUPIED")
	var epoch int64
	var isFenced bool
	if err = f.pool.QueryRow(f.ctx, `SELECT epoch,target_fenced FROM exclusive_targets WHERE target_device_id=$1`, f.peers[1].ID).Scan(&epoch, &isFenced); err != nil || epoch != 2 || isFenced {
		t.Fatalf("old ACK touched new owner: %v", err)
	}
}

func TestExclusivePreparedExpiryAndEpochOverflow(t *testing.T) {
	f := setup(t)
	f.exec(t, `UPDATE applications SET exclusive_target=true WHERE id=$1`, f.peers[1].ApplicationID)
	v, err := f.prepareExclusive(t, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Move only the prepared deadline backwards, not an issued lease watermark.
	f.exec(t, `UPDATE sessions SET connect_deadline=clock_timestamp()-interval '1 second' WHERE id=$1`, v.ID)
	_, err = f.service.ConnectPrepared(exclusiveContext(f.ctx, v.TargetEpoch, "runtime"), f.peers[0], v.ID)
	code(t, err, "PREPARED_EXPIRED")
	// Dedicated overflow fixture never issues or wraps epoch zero.
	f.exec(t, `INSERT INTO exclusive_targets(tenant_id,target_device_id,epoch) VALUES($1,$2,9223372036854775807)`, f.peers[0].TenantID, f.peers[2].ID)
	f.exec(t, `UPDATE applications SET exclusive_target=true WHERE id=$1`, f.peers[2].ApplicationID)
	_, err = f.prepareExclusive(t, 0, 2)
	code(t, err, "EXCLUSIVE_EPOCH_EXHAUSTED")
	var after time.Time
	if err = f.pool.QueryRow(f.ctx, `SELECT release_not_before FROM exclusive_targets WHERE target_device_id=$1`, f.peers[1].ID).Scan(&after); err != nil || after.Before(*v.ReleaseNotBefore) {
		t.Fatal("deadline high water changed")
	}
}

func TestExclusiveNoACKWaitsActualReleaseDeadline(t *testing.T) {
	f := setup(t)
	f.exec(t, `UPDATE applications SET exclusive_target=true WHERE id=$1`, f.peers[1].ApplicationID)
	tx, err := f.service.begin(f.ctx, f.peers[0].TenantID)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := PrepareExclusiveInTx(f.ctx, tx, f.peers[0].TenantID, f.peers[0].ID, f.peers[1].ID, 1)
	if err != nil {
		rollback(tx)
		t.Fatal(err)
	}
	if err = commit(f.ctx, tx); err != nil {
		t.Fatal(err)
	}
	ctx := exclusiveContext(f.ctx, initial.TargetEpoch, "source-runtime")
	closed, err := f.service.Close(ctx, f.peers[0], initial.ID, "CLIENT_CLOSED")
	if err != nil || closed.ExclusiveReleaseState != "closing" {
		t.Fatal("early release", err)
	}
	_, err = f.prepareExclusive(t, 2, 1)
	code(t, err, "TARGET_OCCUPIED")
	// Wait on the actual persisted high-water deadline, not a guessed fixed sleep.
	for {
		var at time.Time
		if err = f.pool.QueryRow(f.ctx, "SELECT clock_timestamp()").Scan(&at); err != nil {
			t.Fatal(err)
		}
		if !at.Before(*initial.ReleaseNotBefore) {
			break
		}
		select {
		case <-time.After(10 * time.Millisecond):
		case <-f.ctx.Done():
			t.Fatal("deadline timeout")
		}
	}
	next, err := f.prepareExclusive(t, 2, 1)
	if err != nil || next.TargetEpoch != "2" {
		t.Fatalf("time fallback failed %v", err)
	}
	if next.TargetFenced {
		t.Fatal("time fallback invented target acknowledgement")
	}
}

func TestExclusiveLeaseCapAndFenceFailureRollsBack(t *testing.T) {
	f := setup(t)
	f.service.options.LeaseTTL = 5 * time.Minute
	f.exec(t, `UPDATE applications SET exclusive_target=true WHERE id=$1`, f.peers[1].ApplicationID)
	value, err := f.prepareExclusive(t, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx := exclusiveContext(f.ctx, value.TargetEpoch, "accepted-runtime")
	_, err = f.service.ConnectPrepared(ctx, f.peers[0], value.ID)
	if err != nil {
		t.Fatal(err)
	}
	bad := WithExclusiveFenceCheck(ctx, func(context.Context) error { return failure("EXCLUSIVE_FENCE_STALE", 409) })
	_, err = f.service.Respond(bad, f.peers[1], value.ID, true)
	code(t, err, "EXCLUSIVE_FENCE_STALE")
	var raw []byte
	if err = f.pool.QueryRow(f.ctx, `SELECT target_accept_fence_hash FROM sessions WHERE id=$1`, value.ID).Scan(&raw); err != nil || raw != nil {
		t.Fatal("failed accept persisted runtime authority")
	}
	var before time.Time
	if err = f.pool.QueryRow(f.ctx, "SELECT clock_timestamp()").Scan(&before); err != nil {
		t.Fatal(err)
	}
	value, err = f.service.Respond(ctx, f.peers[1], value.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if value.LeaseExpiresAt.After(before.Add(61 * time.Second)) {
		t.Fatal("exclusive accepted five minute lease")
	}
	value, err = f.service.Renew(ctx, f.peers[1], value.ID)
	if err != nil || value.LeaseExpiresAt.After(before.Add(61*time.Second)) {
		t.Fatal("exclusive renew exceeded60", err)
	}
	value, err = f.service.Close(ctx, f.peers[0], value.ID, "CLIENT_CLOSED")
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.service.FenceAck(bad, f.peers[1], value.ID, value.TargetEpoch)
	code(t, err, "EXCLUSIVE_FENCE_STALE")
	var fenced bool
	if err = f.pool.QueryRow(f.ctx, `SELECT target_fenced FROM exclusive_targets WHERE target_device_id=$1`, f.peers[1].ID).Scan(&fenced); err != nil || fenced {
		t.Fatal("failed ACK committed release")
	}
}
