//go:build integration

package signaling

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/authorization"
	"github.com/barry-ran/peerloom/src/device-server/internal/identity"
	"github.com/barry-ran/peerloom/src/device-server/internal/migrate"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type recoveryPresence struct{}

func (recoveryPresence) Online(context.Context, string, string) (bool, error) { return true, nil }

func TestLegacyConnectedFrameOnlyAdmitsGenerationOne(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Fatal("isolated TEST_DATABASE_URL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal("cannot connect to test PostgreSQL")
	}
	defer admin.Close(ctx)
	schema := pgx.Identifier{"signal_recovery_" + uuid()[:8]}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal("invalid database configuration")
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	dir, err := filepath.Abs("../../../../infra/migrations")
	if err != nil {
		t.Fatal(err)
	}
	migrations, err := migrate.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = migrate.Apply(ctx, pool, migrations, "up"); err != nil {
		t.Fatal(err)
	}
	var tenant, app string
	if err = pool.QueryRow(ctx, "INSERT INTO tenants(name) VALUES('legacy frame test') RETURNING id::text").Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, "INSERT INTO applications(tenant_id,name) VALUES($1,'application') RETURNING id::text", tenant).Scan(&app); err != nil {
		t.Fatal(err)
	}
	peers := make([]identity.Device, 2)
	for i := range peers {
		peers[i].TenantID, peers[i].ApplicationID = tenant, app
		if err = pool.QueryRow(ctx, `INSERT INTO devices(tenant_id,application_id,installation_key_hash,platform)
VALUES($1,$2,$3,'linux') RETURNING id::text`, tenant, app, []byte{byte(i + 1)}).Scan(&peers[i].ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = pool.Exec(ctx, `INSERT INTO connection_grants(tenant_id,source_device_id,target_device_id,expires_at,max_sessions)
VALUES($1,$2,$3,clock_timestamp()+interval '1 hour',4)`, tenant, peers[0].ID, peers[1].ID); err != nil {
		t.Fatal(err)
	}
	service, err := authorization.New(pool, recoveryPresence{}, authorization.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	session, err := service.Request(ctx, peers[0], peers[1].ID, uuid())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, "UPDATE sessions SET source_offer_seen=true,target_answer_seen=true WHERE id=$1", session.ID); err != nil {
		t.Fatal(err)
	}
	// Exact legacy envelope shape: connected has no negotiation_generation member.
	wire, err := json.Marshal(map[string]any{"v": 1, "type": "session.connected", "id": uuid(), "session_id": session.ID, "seq": 1, "sent_at": time.Now().UTC().Format(time.RFC3339Nano), "payload": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	frame, err := Decode(wire)
	if err != nil || frame.Negotiation != 0 {
		t.Fatal("legacy frame was not decoded as absent generation")
	}
	for _, invalid := range []any{0, nil} {
		var explicit map[string]any
		if err = json.Unmarshal(wire, &explicit); err != nil {
			t.Fatal(err)
		}
		explicit["negotiation_generation"] = invalid
		malformed, err := json.Marshal(explicit)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = Decode(malformed); err == nil {
			t.Fatal("explicit zero/null generation was mistaken for legacy omission")
		}
	}
	dispatch := AuthorizationDispatch(service)
	if _, err = dispatch(ctx, peers[0], frame); err != nil {
		t.Fatalf("legacy generation-one connected denied: %v", err)
	}
	if _, err = pool.Exec(ctx, "UPDATE sessions SET negotiation_generation=2,source_connected=false WHERE id=$1", session.ID); err != nil {
		t.Fatal(err)
	}
	_, err = dispatch(ctx, peers[0], frame)
	var denied *authorization.Error
	if !errors.As(err, &denied) || denied.Code != "NEGOTIATION_STALE" {
		t.Fatalf("legacy frame reached newer generation: %v", err)
	}
	frame.Negotiation = 2
	if _, err = dispatch(ctx, peers[0], frame); err != nil {
		t.Fatalf("explicit current generation denied: %v", err)
	}
}
