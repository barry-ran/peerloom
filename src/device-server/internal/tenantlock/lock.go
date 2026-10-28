// Package tenantlock supplies the shared transaction serialization primitive
// without importing identity or authorization business logic.
package tenantlock

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"github.com/jackc/pgx/v5"
	"strings"
)

// Acquire requires a validated UUID and precedes every business row lock.
func Acquire(ctx context.Context, tx pgx.Tx, tenantID string) error {
	key := sha256.Sum256([]byte("peerloom-session:" + strings.ToLower(tenantID)))
	_, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", int64(binary.BigEndian.Uint64(key[:8])))
	return err
}
