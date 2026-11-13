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
	return Registration{ApplicationID: seed.ApplicationID, Platform: "linux", InstallationTag: "not-an-authenticator", RegistrationGrant: seed.RegistrationGrant, Metadata: map[string]any{"name": "test"}}
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

func TestConcurrentRegistration(t *testing.T) {
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

func TestLongLivedCredentialRevocationAndDisable(t *testing.T) {
	for _, scenario := range []string{"credential-revoked", "device-revoked", "application-disabled", "tenant-disabled"} {
		t.Run(scenario, func(t *testing.T) {
			store, pool, ctx, _ := identityFixture(t)
			input := seedRegistration(t, ctx, pool)
			credential, err := store.Register(ctx, input, "expiry-negative-register")
			if err != nil {
				t.Fatal(err)
			}
			var statement string
			switch scenario {
			case "credential-revoked":
				statement = "UPDATE device_credentials SET revoked_at=clock_timestamp()"
			case "device-revoked":
				statement = "UPDATE devices SET status='revoked'"
			case "application-disabled":
				statement = "UPDATE applications SET enabled=false"
			case "tenant-disabled":
				statement = "UPDATE tenants SET status='suspended'"
			}
			if _, err := pool.Exec(ctx, statement); err != nil {
				t.Fatal(err)
			}
			got, err := store.Authenticate(ctx, credential.DeviceCredential)
			requireCode(t, err, "AUTH_INVALID")
			if got.ID != "" {
				t.Fatal("failed authentication leaked identity snapshot")
			}
		})
	}
}

func TestLongOfflineIdentitySurvivesRestart(t *testing.T) {
	store, pool, ctx, key := identityFixture(t)
	input := seedRegistration(t, ctx, pool)
	credential, err := store.Register(ctx, input, "long-offline-registration")
	if err != nil {
		t.Fatal(err)
	}
	// Age persistent creation time well beyond the former 24h TTL. There is no
	// credential expiry column, sentinel date, or time-dependent authentication.
	if _, err = pool.Exec(ctx, "UPDATE device_credentials SET created_at=clock_timestamp()-interval '10 years'"); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(pool, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := restarted.Authenticate(ctx, credential.DeviceCredential)
	if err != nil || got.ID != credential.DeviceID {
		t.Fatalf("long-offline identity lost: %v", err)
	}
	var count int
	if err = pool.QueryRow(ctx, "SELECT count(*) FROM device_credentials").Scan(&count); err != nil || count != 1 {
		t.Fatal("authentication rotated credential")
	}
}

func TestLongLivedIdentitySchemaHasNoExpiry(t *testing.T) {
	_, pool, ctx, _ := identityFixture(t)
	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='device_credentials' AND column_name IN ('expires_at','rotated_at')").Scan(&count); err != nil || count != 0 {
		t.Fatalf("legacy credential lifetime columns remain: %d %v", count, err)
	}
}
