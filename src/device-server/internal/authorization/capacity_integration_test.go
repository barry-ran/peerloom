//go:build integration

package authorization

import (
	"path/filepath"
	"testing"

	"github.com/barry-ran/peerloom/src/device-server/internal/migrate"
)

func TestUnlimitedCapacityPreservesZeroAndExplicitPolicies(t *testing.T) {
	f := setup(t)
	f.grant(t, 0, 1, "terminate", -1)
	for i := 0; i < 40; i++ {
		f.request(t, 2000+i)
	}
	f.exec(t, "UPDATE applications SET max_connections=0 WHERE id=$1", f.peers[0].ApplicationID)
	_, err := f.service.Request(f.ctx, f.peers[0], f.peers[1].ID, requestID(2100))
	code(t, err, "CONCURRENCY_LIMIT")
	f.exec(t, "UPDATE devices SET max_connections=-1 WHERE id=$1", f.peers[0].ID)
	f.request(t, 2101)
	f.exec(t, "UPDATE devices SET max_connections=0 WHERE id=$1", f.peers[0].ID)
	_, err = f.service.Request(f.ctx, f.peers[0], f.peers[1].ID, requestID(2102))
	code(t, err, "CONCURRENCY_LIMIT")
	f.exec(t, "UPDATE devices SET max_connections=NULL WHERE id=$1", f.peers[0].ID)
	_, err = f.service.Request(f.ctx, f.peers[0], f.peers[1].ID, requestID(2103))
	code(t, err, "CONCURRENCY_LIMIT")
	f.exec(t, "UPDATE applications SET max_connections=-1 WHERE id=$1", f.peers[0].ApplicationID)
	f.exec(t, "UPDATE connection_grants SET max_sessions=1")
	_, err = f.service.Request(f.ctx, f.peers[0], f.peers[1].ID, requestID(2104))
	code(t, err, "CONCURRENCY_LIMIT")
}

func TestCapacityMigrationPreservesExistingPolicies(t *testing.T) {
	f := setup(t)
	f.exec(t, "UPDATE applications SET max_connections=8")
	f.exec(t, "UPDATE applications SET max_connections=0 WHERE id=$1", f.peers[0].ApplicationID)
	f.exec(t, "UPDATE devices SET max_connections=0 WHERE id=$1", f.peers[0].ID)
	grantID := f.grant(t, 0, 1, "terminate", 1)
	directory, err := filepath.Abs("../../../../infra/migrations")
	if err != nil {
		t.Fatal(err)
	}
	migrations, err := migrate.Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	// This regression targets migration 10, not whatever later migration exists.
	for version := migrate.CurrentVersion; version > 10; version-- {
		if err = migrate.Apply(f.ctx, f.pool, migrations, "down"); err != nil {
			t.Fatal(err)
		}
	}
	if err = migrate.Apply(f.ctx, f.pool, migrations, "down"); err != nil {
		t.Fatal(err)
	}
	if err = migrate.Apply(f.ctx, f.pool, migrations[:10], "up"); err != nil {
		t.Fatal(err)
	}
	var application, device, grant int
	if err = f.pool.QueryRow(f.ctx, `SELECT a.max_connections,d.max_connections,g.max_sessions FROM applications a JOIN devices d ON d.application_id=a.id JOIN connection_grants g ON g.source_device_id=d.id WHERE g.id=$1`, grantID).Scan(&application, &device, &grant); err != nil {
		t.Fatal(err)
	}
	if application != 0 || device != 0 || grant != 1 {
		t.Fatal("historical zero/positive policies changed")
	}
	if err = f.pool.QueryRow(f.ctx, "SELECT max_connections FROM applications WHERE id=$1", f.peers[1].ApplicationID).Scan(&application); err != nil || application != 8 {
		t.Fatal("historical8 changed", err)
	}
	if err = f.pool.QueryRow(f.ctx, "INSERT INTO applications(tenant_id,name) VALUES($1,'new default') RETURNING max_connections", f.peers[0].TenantID).Scan(&application); err != nil || application != -1 {
		t.Fatal("new default not unlimited", err)
	}
	if err = migrate.Apply(f.ctx, f.pool, migrations, "down"); err == nil {
		t.Fatal("rollback silently altered unlimited policy")
	}
}
