//go:build integration

package authorization

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// The fixture owns a fresh random schema. Execute the exact shipped downgrade
// inside a transaction, and roll even the successful downgrade back; no shared
// schema, migration ledger, or concurrently running test is changed.
func TestExclusiveDowngradeRejectsUnreleasedAndRollsBackAtomically(t *testing.T) {
	f := setup(t)
	f.exec(t, `UPDATE applications SET exclusive_target=true WHERE id=$1`, f.peers[1].ApplicationID)
	value, err := f.prepareExclusive(t, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx := exclusiveContext(f.ctx, value.TargetEpoch, "downgrade-original-target-runtime")
	if _, err = f.service.ConnectPrepared(ctx, f.peers[0], value.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.Respond(ctx, f.peers[1], value.ID, true); err != nil {
		t.Fatal(err)
	}
	path, err := filepath.Abs("../../../../infra/migrations/000011_exclusive_sessions.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	assertIntact := func(wantState string, wantFenced bool) {
		t.Helper()
		var intact bool
		err := f.pool.QueryRow(f.ctx, `SELECT
   to_regclass('exclusive_targets') IS NOT NULL AND to_regclass('exclusive_prepare_requests') IS NOT NULL
   AND EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='sessions' AND column_name='target_epoch')
   AND EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='applications' AND column_name='exclusive_target')
   AND EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='sessions'::regclass AND tgname='exclusive_deadline')`).Scan(&intact)
		if err != nil || !intact {
			t.Fatalf("downgrade left partial schema: %v", err)
		}
		var state, epoch string
		var fenced bool
		if err = f.pool.QueryRow(f.ctx, `SELECT state,target_epoch::text,target_fenced FROM sessions WHERE id=$1`, value.ID).Scan(&state, &epoch, &fenced); err != nil || state != wantState || epoch != value.TargetEpoch || fenced != wantFenced {
			t.Fatalf("downgrade changed authority row: %v", err)
		}
		var version int64
		if err = f.pool.QueryRow(f.ctx, `SELECT max(version) FROM schema_migrations`).Scan(&version); err != nil || version != 11 {
			t.Fatalf("migration ledger changed: %v", err)
		}
	}
	attempt := func(reject bool, state string, fenced bool) {
		t.Helper()
		tx, err := f.pool.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer rollback(tx)
		_, err = tx.Exec(f.ctx, string(down))
		if reject {
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "P0001" || pg.Message != "exclusive sessions must be safely released before downgrade" {
				t.Fatalf("expected explicit unsafe downgrade rejection, got %v", err)
			}
		} else {
			if err != nil {
				t.Fatalf("released downgrade rejected: %v", err)
			}
			var removed bool
			if err = tx.QueryRow(f.ctx, `SELECT to_regclass('exclusive_targets') IS NULL AND to_regclass('exclusive_prepare_requests') IS NULL AND NOT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='sessions' AND column_name='target_epoch') AND NOT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='applications' AND column_name='exclusive_target')`).Scan(&removed); err != nil || !removed {
				t.Fatalf("released downgrade did not execute completely: %v", err)
			}
		}
		if err = tx.Rollback(f.ctx); err != nil {
			t.Fatal(err)
		}
		assertIntact(state, fenced)
	}
	attempt(true, "connecting", false)
	if _, err = f.service.Close(ctx, f.peers[0], value.ID, "CLIENT_CLOSED"); err != nil {
		t.Fatal(err)
	}
	attempt(true, "closed", false)
	if _, err = f.service.FenceAck(ctx, f.peers[1], value.ID, value.TargetEpoch); err != nil {
		t.Fatal(err)
	}
	attempt(false, "closed", true)
}
