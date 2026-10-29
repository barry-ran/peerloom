//go:build integration

package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/migrate"
	"github.com/jackc/pgx/v5/pgxpool"
)

func directFixture(t *testing.T) (*Store, *pgxpool.Pool, context.Context, Registration) {
	t.Helper()
	s, p, c, _ := identityFixture(t)
	input := seedRegistration(t, c, p)
	if _, err := p.Exec(c, "UPDATE applications SET registration_mode='direct' WHERE id=$1", input.ApplicationID); err != nil {
		t.Fatal(err)
	}
	input.RegistrationGrant = ""
	return s, p, c, input
}
func directKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func TestDirectAtomicReplayAndExpiry(t *testing.T) {
	s, p, ctx, input := directFixture(t)
	key := directKey(t)
	start := make(chan struct{})
	values := make(chan Credential, 8)
	errs := make(chan error, 8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			v, e := s.RegisterDirect(ctx, input, key, "192.0.2.1")
			values <- v
			errs <- e
		}()
	}
	close(start)
	wg.Wait()
	close(values)
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	var original Credential
	for v := range values {
		if original.DeviceID == "" {
			original = v
		} else if v != original {
			t.Fatal("concurrent retry changed identity")
		}
	}
	var devices, receipts int
	if err := p.QueryRow(ctx, "SELECT (SELECT count(*) FROM devices),(SELECT count(*) FROM direct_registration_receipts)").Scan(&devices, &receipts); err != nil || devices != 1 || receipts != 1 {
		t.Fatal("non-atomic duplicate registration")
	}
	changed := input
	changed.InstallationPublicKey = "changed-public-installation"
	_, err := s.RegisterDirect(ctx, changed, key, "192.0.2.1")
	requireCode(t, err, "IDEMPOTENCY_CONFLICT")
	if _, err = p.Exec(ctx, "UPDATE identity_replays SET expires_at=clock_timestamp()-interval '1 second'"); err != nil {
		t.Fatal(err)
	}
	if err = s.PurgeExpired(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = s.RegisterDirect(ctx, input, key, "192.0.2.1")
	requireCode(t, err, "REPLAY_EXPIRED")
	if err = p.QueryRow(ctx, "SELECT count(*) FROM devices").Scan(&devices); err != nil || devices != 1 {
		t.Fatal("expired replay created second identity")
	}
}
func TestDirectModeAndTenantRevalidation(t *testing.T) {
	s, p, ctx, input := directFixture(t)
	key := directKey(t)
	value, err := s.RegisterDirect(ctx, input, key, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{"UPDATE applications SET enabled=false", "UPDATE applications SET registration_mode='grant'", "UPDATE tenants SET status='suspended'"} {
		if _, err = p.Exec(ctx, query); err != nil {
			t.Fatal(err)
		}
		_, err = s.RegisterDirect(ctx, input, key, "192.0.2.1")
		requireCode(t, err, "DIRECT_REGISTRATION_DISABLED")
		if _, err = p.Exec(ctx, "UPDATE applications SET enabled=true,registration_mode='direct';UPDATE tenants SET status='active'"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = p.Exec(ctx, "UPDATE devices SET status='revoked' WHERE id=$1", value.DeviceID); err != nil {
		t.Fatal(err)
	}
	_, err = s.RegisterDirect(ctx, input, key, "192.0.2.1")
	requireCode(t, err, "AUTH_INVALID")
	foreign := seedRegistration(t, ctx, p)
	foreign.RegistrationGrant = ""
	_, err = s.RegisterDirect(ctx, foreign, directKey(t), "192.0.2.1")
	requireCode(t, err, "DIRECT_REGISTRATION_DISABLED")
}
func TestDirectDurableRateAndDeviceQuota(t *testing.T) {
	t.Run("ip-and-malformed", func(t *testing.T) {
		s, p, ctx, input := directFixture(t)
		s.settings.DirectIPPerMinute = 2
		_, err := s.RegisterDirect(ctx, input, "short", "192.0.2.1")
		requireCode(t, err, "DIRECT_RECOVERY_KEY_REQUIRED")
		_, err = s.RegisterDirect(ctx, input, "short", "::ffff:192.0.2.1")
		requireCode(t, err, "DIRECT_RECOVERY_KEY_REQUIRED")
		// Reconstruct the service: limiter authority cannot live in process memory.
		next, err := NewWithSettings(p, make([]byte, 32), s.settings)
		if err != nil {
			t.Fatal(err)
		}
		_, err = next.RegisterDirect(ctx, input, directKey(t), "192.0.2.1")
		requireCode(t, err, "REGISTRATION_RATE_LIMITED")
	})
	t.Run("ipv6-prefix", func(t *testing.T) {
		s, _, ctx, input := directFixture(t)
		s.settings.DirectIPPerMinute = 1
		_, err := s.RegisterDirect(ctx, input, "short", "2001:db8::1")
		requireCode(t, err, "DIRECT_RECOVERY_KEY_REQUIRED")
		_, err = s.RegisterDirect(ctx, input, directKey(t), "2001:db8::2")
		requireCode(t, err, "REGISTRATION_RATE_LIMITED")
	})
	t.Run("global", func(t *testing.T) {
		s, _, ctx, input := directFixture(t)
		s.settings.DirectGlobalPerMinute = 1
		_, err := s.RegisterDirect(ctx, input, "short", "192.0.2.1")
		requireCode(t, err, "DIRECT_RECOVERY_KEY_REQUIRED")
		_, err = s.RegisterDirect(ctx, input, directKey(t), "192.0.2.2")
		requireCode(t, err, "REGISTRATION_RATE_LIMITED")
	})
	t.Run("application-and-replay", func(t *testing.T) {
		s, p, ctx, input := directFixture(t)
		s.settings.DirectAppPerMinute = 1
		key := directKey(t)
		if _, err := s.RegisterDirect(ctx, input, key, "192.0.2.1"); err != nil {
			t.Fatal(err)
		}
		// First prove that real enrollment charged the durable app counter.
		hash := digest("peerloom-direct:app:" + input.ApplicationID)
		var charged int
		if err := p.QueryRow(ctx, "SELECT sum(attempts) FROM direct_registration_windows WHERE key_hash=$1", hash).Scan(&charged); err != nil || charged != 1 {
			t.Fatalf("initial durable application charge: %d, %v", charged, err)
		}
		// This isolated fixture has a 60-second context. Seed only its current
		// and next minute as exhausted, so the rejection assertion also holds
		// when the wall clock crosses a minute between the two API calls.
		// Production clocks, admission limits and replay handling are unchanged.
		if _, err := p.Exec(ctx, `WITH instant AS MATERIALIZED (SELECT date_trunc('minute',clock_timestamp()) AS minute)
INSERT INTO direct_registration_windows(key_hash,window_start,attempts)
SELECT $1,minute+offsets.delta,1 FROM instant CROSS JOIN (VALUES(interval '0 minutes'),(interval '1 minute')) AS offsets(delta)
ON CONFLICT(key_hash,window_start) DO UPDATE SET attempts=EXCLUDED.attempts`, hash); err != nil {
			t.Fatal(err)
		}
		_, err := s.RegisterDirect(ctx, input, key, "192.0.2.2")
		requireCode(t, err, "REGISTRATION_RATE_LIMITED")
		if err := p.QueryRow(ctx, "SELECT max(attempts) FROM direct_registration_windows WHERE key_hash=$1", hash).Scan(&charged); err != nil || charged != 1 {
			t.Fatalf("exhausted replay must not overflow its durable counter: %d, %v", charged, err)
		}
	})
	for _, daily := range []bool{false, true} {
		t.Run(map[bool]string{false: "total", true: "daily"}[daily], func(t *testing.T) {
			s, p, ctx, input := directFixture(t)
			if daily {
				s.settings.DirectAppPerDay = 1
			} else {
				s.settings.DirectAppDevices = 1
			}
			var wg sync.WaitGroup
			out := make(chan error, 4)
			for i := 0; i < 4; i++ {
				key := directKey(t)
				wg.Add(1)
				go func() { defer wg.Done(); _, err := s.RegisterDirect(ctx, input, key, "192.0.2.1"); out <- err }()
			}
			wg.Wait()
			close(out)
			success := 0
			for err := range out {
				if err == nil {
					success++
				} else {
					requireCode(t, err, "REGISTRATION_QUOTA_EXCEEDED")
				}
			}
			if success != 1 {
				t.Fatalf("quota admitted %d", success)
			}
			var count int
			if err := p.QueryRow(ctx, "SELECT count(*) FROM devices").Scan(&count); err != nil || count != 1 {
				t.Fatal("quota overshot")
			}
		})
	}
}
func TestDirectRecoverySecretNeverStoredPlain(t *testing.T) {
	s, p, ctx, input := directFixture(t)
	key := directKey(t)
	v, err := s.RegisterDirect(ctx, input, key, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"direct_registration_receipts", "direct_registration_windows", "identity_replays", "device_credentials", "audit_events"} {
		rows, err := p.Query(ctx, "SELECT row_to_json(t)::text FROM "+table+" t")
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var row string
			if err = rows.Scan(&row); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(row, key) || strings.Contains(row, v.DeviceCredential) || strings.Contains(row, "192.0.2.1") {
				t.Fatal("plaintext credential/recovery key/IP persisted")
			}
		}
		rows.Close()
		if rows.Err() != nil {
			t.Fatal(rows.Err())
		}
	}
}

func TestDirectCrossTenantReceiptIsolation(t *testing.T) {
	s, p, ctx, first := directFixture(t)
	second := seedRegistration(t, ctx, p)
	second.RegistrationGrant = ""
	if _, err := p.Exec(ctx, "UPDATE applications SET registration_mode='direct' WHERE id=$1", second.ApplicationID); err != nil {
		t.Fatal(err)
	}
	key := directKey(t)
	a, err := s.RegisterDirect(ctx, first, key, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.RegisterDirect(ctx, second, key, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	da, err := s.Authenticate(ctx, a.DeviceCredential)
	if err != nil {
		t.Fatal(err)
	}
	db, err := s.Authenticate(ctx, b.DeviceCredential)
	if err != nil {
		t.Fatal(err)
	}
	if da.TenantID == db.TenantID || da.ApplicationID != first.ApplicationID || db.ApplicationID != second.ApplicationID || a.DeviceID == b.DeviceID {
		t.Fatal("tenant/app authority or receipt scope mixed")
	}
	again, err := s.RegisterDirect(ctx, first, key, "192.0.2.1")
	if err != nil || again != a {
		t.Fatal("cross-tenant attempt changed original receipt")
	}
}

// A previous minute's exhausted bucket must not forbid a legitimate replay in
// the next minute. Move only test-owned counter data; never alter the DB clock.
func TestDirectApplicationQuotaMinuteRollover(t *testing.T) {
	s, p, ctx, input := directFixture(t)
	s.settings.DirectAppPerMinute = 1
	key := directKey(t)
	first, err := s.RegisterDirect(ctx, input, key, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	hash := digest("peerloom-direct:app:" + input.ApplicationID)
	var charged int
	if err = p.QueryRow(ctx, "SELECT sum(attempts) FROM direct_registration_windows WHERE key_hash=$1", hash).Scan(&charged); err != nil || charged != 1 {
		t.Fatalf("first charge: %d %v", charged, err)
	}
	if _, err = p.Exec(ctx, "UPDATE direct_registration_windows SET window_start=date_trunc('minute',clock_timestamp())-interval '1 minute' WHERE key_hash=$1", hash); err != nil {
		t.Fatal(err)
	}
	replay, err := s.RegisterDirect(ctx, input, key, "192.0.2.2")
	if err != nil || replay != first {
		t.Fatalf("new minute replay must reuse identity: %v", err)
	}
	var windows int
	if err = p.QueryRow(ctx, "SELECT count(*),sum(attempts) FROM direct_registration_windows WHERE key_hash=$1", hash).Scan(&windows, &charged); err != nil || windows != 2 || charged != 2 {
		t.Fatalf("rollover counters: %d/%d %v", windows, charged, err)
	}
}

func TestDirectUnlimitedDefaultsKeepIdentitySecurityWithoutCounters(t *testing.T) {
	s, p, ctx, input := directFixture(t)
	// Efficiently seed the former 10,000-device/500-daily ceilings in this owned
	// schema; no credentials or real installations are fabricated outside it.
	if _, err := p.Exec(ctx, `INSERT INTO devices(tenant_id,application_id,installation_key_hash,platform)
 SELECT tenant_id,id,decode(repeat('00',32),'hex'),'linux' FROM applications CROSS JOIN generate_series(1,10000) WHERE id=$1`, input.ApplicationID); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO direct_registration_receipts(tenant_id,application_id,key_hash,request_hash,device_id)
 SELECT tenant_id,application_id,decode(md5(id::text)||md5(id::text),'hex'),decode(repeat('00',32),'hex'),id FROM devices WHERE application_id=$1 LIMIT 500`, input.ApplicationID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterDirect(ctx, input, "invalid", "192.0.2.1"); err == nil {
		t.Fatal("unlimited must not bypass recovery secret validation")
	}
	key := directKey(t)
	first, err := s.RegisterDirect(ctx, input, key, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	replay, err := s.RegisterDirect(ctx, input, key, "192.0.2.2")
	if err != nil || replay != first {
		t.Fatalf("unlimited replay identity: %v", err)
	}
	var devices, receipts, windows int
	if err = p.QueryRow(ctx, `SELECT (SELECT count(*) FROM devices WHERE application_id=$1),(SELECT count(*) FROM direct_registration_receipts WHERE application_id=$1),(SELECT count(*) FROM direct_registration_windows)`, input.ApplicationID).Scan(&devices, &receipts, &windows); err != nil || devices != 10001 || receipts != 501 || windows != 0 {
		t.Fatalf("unlimited defaults accounting %d/%d/%d: %v", devices, receipts, windows, err)
	}
}
func TestDirectPositiveCounterBeyondFormerCeilingAndNoOverflow(t *testing.T) {
	s, p, ctx, _ := directFixture(t)
	for _, limit := range []int{6002, 2147483647} {
		key := fmt.Sprintf("explicit:%d", limit)
		hash := digest("peerloom-direct:" + key)
		if _, err := p.Exec(ctx, `WITH instant AS MATERIALIZED (SELECT date_trunc('minute',clock_timestamp()) AS minute)
INSERT INTO direct_registration_windows(key_hash,window_start,attempts)
SELECT $1,minute+offsets.delta,$2 FROM instant CROSS JOIN (VALUES(interval '0 minutes'),(interval '1 minute')) AS offsets(delta)`, hash, limit-1); err != nil {
			t.Fatal(err)
		}
		if err := s.directAdmission(ctx, []directBucket{{key, limit}}); err != nil {
			t.Fatal("last positive permit rejected", limit, err)
		}
		// Exhaust both covered minute buckets before the denial assertion; this is
		// test data only and prevents a real minute boundary from changing its meaning.
		if _, err := p.Exec(ctx, "UPDATE direct_registration_windows SET attempts=$2 WHERE key_hash=$1", hash, limit); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ {
			requireCode(t, s.directAdmission(ctx, []directBucket{{key, limit}}), "REGISTRATION_RATE_LIMITED")
		}
		var minimum, maximum int
		if err := p.QueryRow(ctx, "SELECT min(attempts),max(attempts) FROM direct_registration_windows WHERE key_hash=$1", hash).Scan(&minimum, &maximum); err != nil || minimum != limit || maximum != limit {
			t.Fatal("counter overflow or policy changed", limit, err)
		}
	}
}
func TestDirectCounterMigrationPreservesRowsAndRollbackFailsClosed(t *testing.T) {
	_, p, ctx, _ := directFixture(t)
	if _, err := p.Exec(ctx, "UPDATE applications SET max_connections=8"); err != nil {
		t.Fatal(err)
	}
	hash := digest("owned-counter-migration")
	if _, err := p.Exec(ctx, "INSERT INTO direct_registration_windows VALUES($1,date_trunc('minute',clock_timestamp()),6001)", hash); err != nil {
		t.Fatal(err)
	}
	directory, err := filepath.Abs("../../../../infra/migrations")
	if err != nil {
		t.Fatal(err)
	}
	migrations, err := migrate.Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	assertVersion := func(want int64) {
		t.Helper()
		var version int64
		if err := p.QueryRow(ctx, "SELECT max(version) FROM schema_migrations").Scan(&version); err != nil || version != want {
			t.Fatalf("migration version = %d, want %d: %v", version, want, err)
		}
	}
	// The fixture starts at schema 11. First remove the unrelated exclusive
	// migration, then exercise precisely the historical 9 -> 10 transition.
	assertVersion(11)
	if err = migrate.Apply(ctx, p, migrations, "down"); err != nil {
		t.Fatal(err)
	}
	assertVersion(10)
	capacityMigrations := migrations[:10]
	if err = migrate.Apply(ctx, p, capacityMigrations, "down"); err != nil {
		t.Fatal(err)
	}
	assertVersion(9)
	if err = migrate.Apply(ctx, p, capacityMigrations, "up"); err != nil {
		t.Fatal(err)
	}
	assertVersion(10)
	var attempts int
	if err = p.QueryRow(ctx, "SELECT attempts FROM direct_registration_windows WHERE key_hash=$1", hash).Scan(&attempts); err != nil || attempts != 6001 {
		t.Fatal("migration rewrote historical count", err)
	}
	if _, err = p.Exec(ctx, "UPDATE direct_registration_windows SET attempts=6002 WHERE key_hash=$1", hash); err != nil {
		t.Fatal(err)
	}
	rollbackCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err = migrate.Apply(rollbackCtx, p, capacityMigrations, "down"); err == nil || err.Error() != "migration 10 down failed" {
		t.Fatal("rollback must reject the schema 10 counter constraint", err)
	}
	assertVersion(10)
	if err = p.QueryRow(ctx, "SELECT attempts FROM direct_registration_windows WHERE key_hash=$1", hash).Scan(&attempts); err != nil || attempts != 6002 {
		t.Fatal("failed rollback changed count", err)
	}
}
