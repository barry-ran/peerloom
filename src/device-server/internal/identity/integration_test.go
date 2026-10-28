//go:build integration

package identity

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/migrate"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func identityFixture(t *testing.T) (*Store, *pgxpool.Pool, context.Context, []byte) {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Fatal("integration target requires isolated TEST_DATABASE_URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	admin, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal("cannot connect to test PostgreSQL")
	}
	random := make([]byte, 8)
	if _, err = rand.Read(random); err != nil {
		t.Fatal(err)
	}
	schema := "peerloom_identity_" + hex.EncodeToString(random)
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal("invalid test database URL")
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_, _ = admin.Exec(cleanup, "DROP SCHEMA "+quoted+" CASCADE")
		_ = admin.Close(cleanup)
	})
	dir, err := filepath.Abs("../../../../infra/migrations")
	if err != nil {
		t.Fatal(err)
	}
	ms, err := migrate.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = migrate.Apply(ctx, pool, ms, "up"); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		t.Fatal(err)
	}
	store, err := New(pool, key)
	if err != nil {
		t.Fatal(err)
	}
	return store, pool, ctx, key
}

func seedRegistration(t *testing.T, ctx context.Context, pool *pgxpool.Pool) Registration {
	t.Helper()
	seed, err := BootstrapDevelopment(ctx, pool, "测试租户")
	if err != nil {
		t.Fatal(err)
	}
	return Registration{ApplicationID: seed.ApplicationID, Platform: "linux", InstallationPublicKey: "not-an-authenticator", RegistrationGrant: seed.RegistrationGrant, Metadata: map[string]any{"name": "test"}}
}

func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	var actual *Error
	if !errors.As(err, &actual) || actual.Code != code {
		t.Fatalf("expected %s, got %v", code, err)
	}
}

func TestRegistrationDurabilityAndIsolation(t *testing.T) {
	store, pool, ctx, key := identityFixture(t)
	input := seedRegistration(t, ctx, pool)
	first, err := store.Register(ctx, input, "registration-request-one")
	if err != nil {
		t.Fatal(err)
	}
	// A new pool and store have no previous process-local request state.
	freshPool, err := pgxpool.NewWithConfig(ctx, pool.Config())
	if err != nil {
		t.Fatal(err)
	}
	defer freshPool.Close()
	restarted, err := New(freshPool, key)
	if err != nil {
		t.Fatal(err)
	}
	again, err := restarted.Register(ctx, input, "registration-request-one")
	if err != nil {
		t.Fatal(err)
	}
	if first != again {
		t.Fatal("durable replay changed identity or credential")
	}
	var count int
	if err = pool.QueryRow(ctx, "SELECT count(*) FROM devices").Scan(&count); err != nil || count != 1 {
		t.Fatal("replay created multiple devices")
	}
	var ciphertext, hash []byte
	if err = pool.QueryRow(ctx, "SELECT ciphertext FROM identity_replays").Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte(first.DeviceCredential)) {
		t.Fatal("plaintext credential persisted in replay")
	}
	if err = pool.QueryRow(ctx, "SELECT credential_hash FROM device_credentials").Scan(&hash); err != nil || !bytes.Equal(hash, digest(first.DeviceCredential)) {
		t.Fatal("credential hash mismatch")
	}
	changed := input
	changed.Metadata = map[string]any{"name": "changed"}
	_, err = store.Register(ctx, changed, "registration-request-one")
	requireCode(t, err, "IDEMPOTENCY_CONFLICT")
	_, err = store.Register(ctx, input, "different-request-key")
	requireCode(t, err, "GRANT_CONSUMED")
	wrongKey := bytes.Repeat([]byte{42}, 32)
	wrongStore, _ := New(pool, wrongKey)
	_, err = wrongStore.Register(ctx, input, "registration-request-one")
	requireCode(t, err, "REPLAY_UNAVAILABLE")
	other := seedRegistration(t, ctx, pool)
	other.ApplicationID = input.ApplicationID
	_, err = store.Register(ctx, other, "cross-tenant-request")
	requireCode(t, err, "GRANT_INVALID")
	_, err = store.Authenticate(ctx, input.RegistrationGrant)
	requireCode(t, err, "AUTH_INVALID")
	_, err = store.Authenticate(ctx, "admin_anything")
	requireCode(t, err, "AUTH_INVALID")
	device, err := store.Authenticate(ctx, first.DeviceCredential)
	if err != nil || device.ID != first.DeviceID {
		t.Fatal("valid device authentication failed")
	}
	// Reusing a public installation label with a new authorized grant is a new identity,
	// never a way to recover another device's credential.
	newInput := seedRegistration(t, ctx, pool)
	newResult, err := store.Register(ctx, newInput, "fresh-registration")
	if err != nil {
		t.Fatal(err)
	}
	if newResult.DeviceID == first.DeviceID || newResult.DeviceCredential == first.DeviceCredential {
		t.Fatal("public key took over previous identity")
	}
}

func TestConcurrentRegistrationAndRotation(t *testing.T) {
	store, pool, ctx, _ := identityFixture(t)
	input := seedRegistration(t, ctx, pool)
	var wg sync.WaitGroup
	results := make([]Credential, 8)
	errs := make([]error, 8)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = store.Register(ctx, input, "concurrent-registration")
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
		if results[i] != results[0] {
			t.Fatal("concurrent registration returned different credentials")
		}
	}
	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM devices").Scan(&count); err != nil || count != 1 {
		t.Fatal("concurrent registration exceeded one identity")
	}
	old := results[0]
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = store.Refresh(ctx, old.DeviceCredential, "concurrent-rotation")
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
		if results[i] != results[0] {
			t.Fatal("concurrent rotation issued multiple successors")
		}
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM device_credentials").Scan(&count); err != nil || count != 2 {
		t.Fatal("unexpected credential count")
	}
	_, err := store.Refresh(ctx, old.DeviceCredential, "another-rotation-key")
	requireCode(t, err, "CREDENTIAL_ALREADY_ROTATED")
	if _, err = store.Authenticate(ctx, old.DeviceCredential); err != nil {
		t.Fatal("overlap window missing")
	}
	replayedOld, err := store.Register(ctx, input, "concurrent-registration")
	if err != nil {
		t.Fatal(err)
	}
	if replayedOld.DeviceCredential != old.DeviceCredential || replayedOld.ExpiresAt == old.ExpiresAt {
		t.Fatal("registration replay advertised stale pre-rotation lifetime")
	}
	effectiveExpiry, err := time.Parse(time.RFC3339Nano, replayedOld.ExpiresAt)
	if err != nil || time.Until(effectiveExpiry) > time.Minute {
		t.Fatal("replay expiry exceeds overlap window")
	}
	if _, err = pool.Exec(ctx, "UPDATE device_credentials SET expires_at=clock_timestamp()-interval '1 second' WHERE credential_hash=$1", digest(old.DeviceCredential)); err != nil {
		t.Fatal(err)
	}
	_, err = store.Authenticate(ctx, old.DeviceCredential)
	requireCode(t, err, "AUTH_INVALID")
	if _, err = store.Authenticate(ctx, results[0].DeviceCredential); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, "UPDATE devices SET status='revoked' WHERE id=$1", old.DeviceID); err != nil {
		t.Fatal(err)
	}
	_, err = store.Authenticate(ctx, results[0].DeviceCredential)
	requireCode(t, err, "AUTH_INVALID")
}

func TestExpiryDisableAndReplayPurge(t *testing.T) {
	store, pool, ctx, _ := identityFixture(t)
	input := seedRegistration(t, ctx, pool)
	if _, err := pool.Exec(ctx, "UPDATE registration_grants SET expires_at=clock_timestamp()-interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	_, err := store.Register(ctx, input, "expired-grant-request")
	requireCode(t, err, "GRANT_EXPIRED")
	input = seedRegistration(t, ctx, pool)
	if _, err = pool.Exec(ctx, "UPDATE applications SET enabled=false WHERE id=$1", input.ApplicationID); err != nil {
		t.Fatal(err)
	}
	_, err = store.Register(ctx, input, "disabled-app-request")
	requireCode(t, err, "GRANT_INVALID")
	input = seedRegistration(t, ctx, pool)
	if _, err = store.Register(ctx, input, "replay-expire-request"); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, "UPDATE identity_replays SET expires_at=clock_timestamp()-interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	_, err = store.Register(ctx, input, "replay-expire-request")
	requireCode(t, err, "REPLAY_EXPIRED")
	if err = store.PurgeExpired(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = store.Register(ctx, input, "replay-expire-request")
	requireCode(t, err, "GRANT_CONSUMED")
}

func TestRefreshCannotRaceCredentialRevocation(t *testing.T) {
	store, pool, ctx, _ := identityFixture(t)
	input := seedRegistration(t, ctx, pool)
	credential, err := store.Register(ctx, input, "revoke-race-registration")
	if err != nil {
		t.Fatal(err)
	}
	holder, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(holder)
	if _, err = holder.Exec(ctx, "SELECT id FROM device_credentials WHERE credential_hash=$1 FOR UPDATE", digest(credential.DeviceCredential)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := store.Refresh(ctx, credential.DeviceCredential, "revoke-race-refresh")
		done <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	waiting := false
	for time.Now().Before(deadline) {
		if err = pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT id::text,rotated_at FROM device_credentials%')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !waiting {
		t.Fatal("refresh never reached credential lock barrier")
	}
	if _, err = holder.Exec(ctx, "UPDATE device_credentials SET revoked_at=clock_timestamp() WHERE credential_hash=$1", digest(credential.DeviceCredential)); err != nil {
		t.Fatal(err)
	}
	if err = holder.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-done:
		requireCode(t, err, "AUTH_INVALID")
	case <-ctx.Done():
		t.Fatal("refresh deadlocked after revocation")
	}
	var count int
	if err = pool.QueryRow(ctx, "SELECT count(*) FROM device_credentials").Scan(&count); err != nil || count != 1 {
		t.Fatal("revoked credential minted a successor")
	}
}
