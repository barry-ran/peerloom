//go:build integration

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/identity"
	"github.com/barry-ran/peerloom/src/device-server/internal/migrate"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDevelopmentPairUsesRealRegistrations(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Fatal("integration target requires isolated TEST_DATABASE_URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal("cannot connect to test database")
	}
	defer admin.Close(context.Background())
	random := make([]byte, 8)
	if _, err = rand.Read(random); err != nil {
		t.Fatal(err)
	}
	schema := "peerloom_pair_" + hex.EncodeToString(random)
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_, _ = admin.Exec(cleanup, "DROP SCHEMA "+quoted+" CASCADE")
	}()
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal("invalid test database URL")
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
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
	result, err := createPair(ctx, pool, key, identity.DefaultSettings(), "测试配对")
	if err != nil {
		t.Fatal(err)
	}
	store, err := identity.New(pool, key)
	if err != nil {
		t.Fatal(err)
	}
	source, err := store.Authenticate(ctx, result.Source.DeviceCredential)
	if err != nil {
		t.Fatal("source registration credential invalid")
	}
	target, err := store.Authenticate(ctx, result.Target.DeviceCredential)
	if err != nil {
		t.Fatal("target registration credential invalid")
	}
	if source.TenantID != target.TenantID || source.ApplicationID == target.ApplicationID || source.ID != result.Source.DeviceID || target.ID != result.Target.DeviceID {
		t.Fatal("pair scope mismatch")
	}
	var approval bool
	if err = pool.QueryRow(ctx, "SELECT require_target_approval FROM applications WHERE id=$1", target.ApplicationID).Scan(&approval); err != nil || !approval {
		t.Fatal("target confirmation not required")
	}
	var count int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM connection_grants WHERE tenant_id=$1 AND source_device_id=$2 AND target_device_id=$3
AND max_sessions=1 AND expiry_action='terminate' AND expires_at>clock_timestamp()`, source.TenantID, source.ID, target.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("directional grant missing")
	}
}
