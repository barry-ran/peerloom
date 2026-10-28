//go:build integration

package presence

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func integrationRedis(t *testing.T) (*redis.Client, context.Context) {
	t.Helper()
	raw := os.Getenv("TEST_REDIS_URL")
	if raw == "" {
		t.Fatal("integration target requires TEST_REDIS_URL for an isolated Redis test instance")
	}
	options, err := redis.ParseURL(raw)
	if err != nil {
		t.Fatal("invalid test Redis configuration")
	}
	options.DialTimeout = time.Second
	options.ReadTimeout = time.Second
	options.WriteTimeout = time.Second
	options.MaxRetries = -1
	client := redis.NewClient(options)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(func() { cancel(); _ = client.Close() })
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatal("cannot connect to authenticated test Redis")
	}
	return client, ctx
}

func randomID(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	s := hex.EncodeToString(b[:])
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}

func isolatedDevice(t *testing.T, client *redis.Client, tenant string) string {
	t.Helper()
	device := randomID(t)
	key, counter := keys(tenant, device)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		// Never FLUSHDB: remove only the exact UUID-scoped keys owned by this test.
		if err := client.Del(ctx, key, counter).Err(); err != nil {
			t.Errorf("test key cleanup failed")
		}
	})
	return device
}

func mustClaim(t *testing.T, s *Redis, ctx context.Context, tenant, device string) Lease {
	t.Helper()
	lease, err := s.Claim(ctx, tenant, device)
	if err != nil {
		t.Fatal(err)
	}
	if lease.Generation < 1 || len(lease.Token) != 64 {
		t.Fatal("invalid lease identity")
	}
	return lease
}

func TestRedisLeaseExpiryAndCurrentOwnerRenewal(t *testing.T) {
	client, ctx := integrationRedis(t)
	tenant := randomID(t)
	device := isolatedDevice(t, client, tenant)
	store := NewRedis(client)
	if online, err := store.Online(ctx, tenant, device); err != nil || online {
		t.Fatalf("absent device online: %v, %v", online, err)
	}
	lease := mustClaim(t, store, ctx, tenant, device)
	if online, err := store.Online(ctx, tenant, device); err != nil || !online {
		t.Fatalf("current device offline: %v, %v", online, err)
	}
	key, _ := keys(tenant, device)
	if err := client.PExpire(ctx, key, time.Second).Err(); err != nil {
		t.Fatal(err)
	}
	if err := store.Renew(ctx, tenant, device, lease); err != nil {
		t.Fatal(err)
	}
	ttl, err := client.PTTL(ctx, key).Result()
	if err != nil || ttl < LeaseTTL-time.Second || ttl > LeaseTTL {
		t.Fatalf("renewal TTL invalid: %v, %v", ttl, err)
	}
	if err := client.PExpire(ctx, key, time.Millisecond).Err(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		exists, err := client.Exists(ctx, key).Result()
		if err != nil {
			t.Fatal(err)
		}
		if exists == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("lease did not expire within test deadline")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if online, err := store.Online(ctx, tenant, device); err != nil || online {
		t.Fatalf("expired device online: %v, %v", online, err)
	}
	if err := store.Renew(ctx, tenant, device, lease); !errors.Is(err, ErrFenced) {
		t.Fatalf("expired lease resurrected: %v", err)
	}
	if err := store.Release(ctx, tenant, device, lease); err != nil {
		t.Fatal(err)
	}
}

func TestRedisStaleOwnerCannotRenewOrReleaseReplacement(t *testing.T) {
	client, ctx := integrationRedis(t)
	tenant := randomID(t)
	device := isolatedDevice(t, client, tenant)
	store := NewRedis(client)
	old := mustClaim(t, store, ctx, tenant, device)
	current := mustClaim(t, store, ctx, tenant, device)
	if current.Generation != old.Generation+1 || current.Token == old.Token {
		t.Fatal("replacement identity was reused")
	}
	if err := store.Renew(ctx, tenant, device, old); !errors.Is(err, ErrFenced) {
		t.Fatalf("old heartbeat accepted: %v", err)
	}
	if err := store.Release(ctx, tenant, device, old); err != nil {
		t.Fatal(err)
	}
	if err := store.Renew(ctx, tenant, device, current); err != nil {
		t.Fatalf("old release removed replacement: %v", err)
	}
	if err := store.Release(ctx, tenant, device, current); err != nil {
		t.Fatal(err)
	}
	if err := store.Release(ctx, tenant, device, current); err != nil {
		t.Fatal("release is not idempotent")
	}
	if err := store.Renew(ctx, tenant, device, current); !errors.Is(err, ErrFenced) {
		t.Fatal("released lease resurrected")
	}
}

func TestRedisTenantIsolationAndLossRecovery(t *testing.T) {
	client, ctx := integrationRedis(t)
	tenant := randomID(t)
	otherTenant := randomID(t)
	device := isolatedDevice(t, client, tenant)
	otherKey, otherCounter := keys(otherTenant, device)
	t.Cleanup(func() { _ = client.Del(context.Background(), otherKey, otherCounter).Err() })
	store := NewRedis(client)
	old := mustClaim(t, store, ctx, tenant, device)
	other := mustClaim(t, store, ctx, otherTenant, device)
	if err := store.Renew(ctx, tenant, randomID(t), old); !errors.Is(err, ErrFenced) {
		t.Fatal("cross-device lease accepted")
	}
	if err := store.Renew(ctx, otherTenant, device, old); !errors.Is(err, ErrFenced) {
		t.Fatal("cross-tenant lease accepted")
	}
	if err := store.Release(ctx, otherTenant, device, old); err != nil {
		t.Fatal(err)
	}
	if err := store.Renew(ctx, otherTenant, device, other); err != nil {
		t.Fatal("cross-tenant release affected owner")
	}
	key, counter := keys(tenant, device)
	if err := client.Del(ctx, key, counter).Err(); err != nil {
		t.Fatal(err)
	}
	recovered := mustClaim(t, store, ctx, tenant, device)
	if recovered.Generation != 1 || recovered.Token == old.Token {
		t.Fatal("recovery reused fencing identity")
	}
	if err := store.Renew(ctx, tenant, device, old); !errors.Is(err, ErrFenced) {
		t.Fatal("old lease accepted after Redis state loss")
	}
	if err := store.Release(ctx, tenant, device, old); err != nil {
		t.Fatal(err)
	}
	if err := store.Renew(ctx, tenant, device, recovered); err != nil {
		t.Fatal("old release removed recovered owner")
	}
}

func TestRedisConcurrentClaimsHaveOneCurrentOwner(t *testing.T) {
	client, ctx := integrationRedis(t)
	tenant := randomID(t)
	device := isolatedDevice(t, client, tenant)
	store := NewRedis(client)
	const count = 32
	leases := make([]Lease, count)
	errs := make([]error, count)
	var wg sync.WaitGroup
	for i := range count {
		wg.Add(1)
		go func(i int) { defer wg.Done(); leases[i], errs[i] = store.Claim(ctx, tenant, device) }(i)
	}
	wg.Wait()
	generations := map[int64]bool{}
	tokens := map[string]bool{}
	winners := 0
	for i, lease := range leases {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		if generations[lease.Generation] || tokens[lease.Token] {
			t.Fatal("claim identity collision")
		}
		generations[lease.Generation] = true
		tokens[lease.Token] = true
		err := store.Renew(ctx, tenant, device, lease)
		if err == nil {
			winners++
		} else if !errors.Is(err, ErrFenced) {
			t.Fatal(err)
		}
	}
	if winners != 1 || !generations[count] {
		t.Fatalf("current owners=%d, generation count=%d", winners, len(generations))
	}
}

func TestRedisUnavailableFailsClosed(t *testing.T) {
	client, ctx := integrationRedis(t)
	// A separately closed client exercises the real Redis adapter failure path
	// without stopping or flushing the shared integration instance.
	failed := redis.NewClient(client.Options())
	if err := failed.Close(); err != nil {
		t.Fatal(err)
	}
	store := NewRedis(failed)
	tenant, device := randomID(t), randomID(t)
	if online, err := store.Online(ctx, tenant, device); err == nil || online {
		t.Fatal("unavailable store did not fail closed")
	}
	lease, err := store.Claim(ctx, tenant, device)
	if err == nil || lease != (Lease{}) {
		t.Fatal("unavailable store issued a lease")
	}
	if err := store.Renew(ctx, tenant, device, Lease{Token: "invalid"}); err == nil {
		t.Fatal("unavailable store renewed a lease")
	}
	if err := store.Release(ctx, tenant, device, Lease{Token: "invalid"}); err == nil {
		t.Fatal("unavailable store reported successful release")
	}
}

func TestRedisRejectedGenerationDoesNotReplaceCurrentOwner(t *testing.T) {
	for _, value := range []string{"9007199254740991", "-1", "not-an-integer"} {
		t.Run(value, func(t *testing.T) {
			client, ctx := integrationRedis(t)
			tenant := randomID(t)
			device := isolatedDevice(t, client, tenant)
			store := NewRedis(client)
			current := mustClaim(t, store, ctx, tenant, device)
			key, counter := keys(tenant, device)
			if err := client.Set(ctx, counter, value, time.Minute).Err(); err != nil {
				t.Fatal(err)
			}
			lease, err := store.Claim(ctx, tenant, device)
			if err == nil || lease != (Lease{}) {
				t.Fatal("invalid generation issued a lease")
			}
			token, err := client.Get(ctx, key).Result()
			if err != nil || token != current.Token {
				t.Fatal("failed claim changed current owner")
			}
			retained, err := client.Get(ctx, counter).Result()
			if err != nil || retained != value {
				t.Fatal("failed claim changed generation counter")
			}
			if err := store.Renew(ctx, tenant, device, current); err != nil {
				t.Fatal("failed claim fenced the valid current owner")
			}
		})
	}
}
