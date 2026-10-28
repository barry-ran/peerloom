//go:build integration

package management

import (
	"path/filepath"
	"testing"

	"github.com/barry-ran/peerloom/src/device-server/internal/migrate"
)

func TestManagementMigrationRollbackAndReapply(t *testing.T) {
	f := setup(t)
	dir, err := filepath.Abs("../../../../infra/migrations")
	if err != nil {
		t.Fatal(err)
	}
	migrations, err := migrate.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = migrate.Apply(f.ctx, f.pool, migrations, "down"); err != nil {
		t.Fatal(err)
	}
	var absent bool
	if err = f.pool.QueryRow(f.ctx, "SELECT to_regclass('tenant_service_credentials') IS NULL AND to_regclass('management_requests') IS NULL").Scan(&absent); err != nil || !absent {
		t.Fatalf("management rollback failed: %v", err)
	}
	if err = migrate.Apply(f.ctx, f.pool, migrations, "up"); err != nil {
		t.Fatal(err)
	}
	if _, err = BootstrapKey(f.ctx, f.pool, "reapplied", ScopeRead, DefaultSettings().ReceiptTTL, "reapply"); err != nil {
		t.Fatal(err)
	}
}
