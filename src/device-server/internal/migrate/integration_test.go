//go:build integration

package migrate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/database"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func integrationPool(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Fatal("integration target requires TEST_DATABASE_URL pointing to an isolated test database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	admin, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal("cannot connect to test PostgreSQL")
	}
	bytes := make([]byte, 8)
	if _, err = rand.Read(bytes); err != nil {
		t.Fatal(err)
	}
	schema := "peerloom_test_" + hex.EncodeToString(bytes)
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal("invalid test database configuration")
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
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
	return pool, ctx
}

func migrationDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs("../../../../infra/migrations")
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestMigrationRoundTripAndConstraints(t *testing.T) {
	pool, ctx := integrationPool(t)
	ms, err := Load(migrationDir(t))
	if err != nil {
		t.Fatal(err)
	}
	ready := database.Ready(pool, CurrentVersion)
	if ready(ctx) == nil {
		t.Fatal("empty database reported ready")
	}
	if err = Apply(ctx, pool, ms, "up"); err != nil {
		t.Fatal(err)
	}
	if err = ready(ctx); err != nil {
		t.Fatal(err)
	}
	if err = Apply(ctx, pool, ms, "up"); err != nil {
		t.Fatal("repeated up failed", err)
	}
	sql, err := os.ReadFile(filepath.Join(migrationDir(t), "tests/tenant_constraints.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, string(sql)); err != nil {
		t.Fatal("negative tenant constraints failed", err)
	}
	changed := append([]Migration(nil), ms...)
	changed[0].Checksum = "changed"
	if err = Apply(ctx, pool, changed, "up"); err == nil {
		t.Fatal("accepted checksum mismatch")
	}
	if err = Apply(ctx, pool, ms, "down"); err != nil {
		t.Fatal(err)
	}
	if ready(ctx) == nil {
		t.Fatal("rolled-back database reported ready")
	}
	if err = Apply(ctx, pool, ms, "up"); err != nil {
		t.Fatal("second migration up failed", err)
	}
	if err = ready(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestFailedMigrationIsAtomic(t *testing.T) {
	pool, ctx := integrationPool(t)
	ms := []Migration{{Version: 1, Name: "initial", Up: "CREATE TABLE should_rollback(id integer); SELECT missing_function();", Down: "DROP TABLE should_rollback;", Checksum: "test"}}
	if err := Apply(ctx, pool, ms, "up"); err == nil {
		t.Fatal("invalid migration succeeded")
	}
	var exists bool
	if err := pool.QueryRow(ctx, "SELECT to_regclass('should_rollback') IS NOT NULL").Scan(&exists); err != nil || exists {
		t.Fatalf("failed migration left partial state: %v", err)
	}
}
