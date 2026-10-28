// Package migrate applies reviewed SQL in a transaction under a database lock.
package migrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const CurrentVersion int64 = 4
const lockID int64 = 0x504545524c4f4f4d

type Migration struct {
	Version  int64
	Name     string
	Up       string
	Down     string
	Checksum string
}

func Load(dir string) ([]Migration, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, errors.New("cannot read migration directory")
	}
	var migrations []Migration
	seen := map[int64]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		stem := strings.TrimSuffix(name, ".up.sql")
		prefix, _, ok := strings.Cut(stem, "_")
		version, err := strconv.ParseInt(prefix, 10, 64)
		if !ok || err != nil || version <= 0 || seen[version] {
			return nil, errors.New("invalid or duplicate migration version")
		}
		seen[version] = true
		up, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, errors.New("cannot read up migration")
		}
		down, err := os.ReadFile(filepath.Join(dir, stem+".down.sql"))
		if err != nil {
			return nil, errors.New("missing down migration")
		}
		if strings.TrimSpace(string(up)) == "" || strings.TrimSpace(string(down)) == "" {
			return nil, errors.New("empty migration")
		}
		digest := sha256.Sum256(append(append(append([]byte{}, up...), 0), down...))
		migrations = append(migrations, Migration{version, stem, string(up), string(down), hex.EncodeToString(digest[:])})
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].Version < migrations[j].Version })
	if len(migrations) == 0 {
		return nil, errors.New("no migrations found")
	}
	for i, m := range migrations {
		if m.Version != int64(i+1) {
			return nil, errors.New("migration versions must be contiguous from one")
		}
	}
	return migrations, nil
}

func Apply(ctx context.Context, pool *pgxpool.Pool, migrations []Migration, direction string) error {
	if direction != "up" && direction != "down" {
		return errors.New("direction must be up or down")
	}
	if len(migrations) == 0 {
		return errors.New("no migrations provided")
	}
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return errors.New("cannot begin migration")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", lockID); err != nil {
		return errors.New("cannot acquire migration lock")
	}
	if _, err = tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
version bigint PRIMARY KEY, name text NOT NULL, checksum text NOT NULL,
applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return errors.New("cannot initialize migration ledger")
	}
	rows, err := tx.Query(ctx, "SELECT version,name,checksum FROM schema_migrations ORDER BY version")
	if err != nil {
		return errors.New("cannot read migration ledger")
	}
	var applied int
	for rows.Next() {
		var version int64
		var name, checksum string
		if err = rows.Scan(&version, &name, &checksum); err != nil {
			rows.Close()
			return errors.New("cannot decode migration ledger")
		}
		if applied >= len(migrations) || migrations[applied].Version != version || migrations[applied].Name != name || migrations[applied].Checksum != checksum {
			rows.Close()
			return errors.New("migration history differs from reviewed files")
		}
		applied++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return errors.New("cannot read migration history")
	}
	if direction == "up" {
		for _, m := range migrations[applied:] {
			if _, err = tx.Exec(ctx, m.Up); err != nil {
				return fmt.Errorf("migration %d up failed", m.Version)
			}
			if _, err = tx.Exec(ctx, "INSERT INTO schema_migrations(version,name,checksum) VALUES($1,$2,$3)", m.Version, m.Name, m.Checksum); err != nil {
				return errors.New("cannot record migration")
			}
		}
	} else if applied > 0 {
		m := migrations[applied-1]
		if _, err = tx.Exec(ctx, m.Down); err != nil {
			return fmt.Errorf("migration %d down failed", m.Version)
		}
		if _, err = tx.Exec(ctx, "DELETE FROM schema_migrations WHERE version=$1", m.Version); err != nil {
			return errors.New("cannot remove migration record")
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return errors.New("migration commit failed; inspect database before retry")
	}
	return nil
}
