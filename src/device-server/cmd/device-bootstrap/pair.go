package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"github.com/barry-ran/peerloom/src/device-server/internal/database"
	"github.com/barry-ran/peerloom/src/device-server/internal/identity"
	"github.com/barry-ran/peerloom/src/device-server/internal/migrate"
	"github.com/jackc/pgx/v5/pgxpool"
)

type pairDevice struct {
	ApplicationID    string `json:"application_id"`
	DeviceID         string `json:"device_id"`
	DeviceCredential string `json:"device_credential"`
	ExpiresAt        string `json:"expires_at"`
}

type pairResult struct {
	Source pairDevice `json:"source"`
	Target pairDevice `json:"target"`
}

// createPair is an explicit development fixture, not a management service.
// It creates a fresh tenant, runs the real registration service twice, and
// adds one same-tenant cross-application grant requiring target consent.
// A failure can leave this newly-created fixture partially provisioned; no
// existing tenant is adopted or deleted, and no public endpoint invokes it.
func createPair(ctx context.Context, pool *pgxpool.Pool, key []byte, settings identity.Settings, name string) (pairResult, error) {
	if err := database.Ready(pool, migrate.CurrentVersion)(ctx); err != nil {
		return pairResult{}, errors.New("pair fixture requires current database migrations")
	}
	store, err := identity.NewWithSettings(pool, key, settings)
	if err != nil {
		return pairResult{}, errors.New("cannot initialize pair identity service")
	}
	seed, err := identity.BootstrapDevelopment(ctx, pool, name)
	if err != nil {
		return pairResult{}, err
	}
	var targetApplication string
	if err = pool.QueryRow(ctx, `INSERT INTO applications(tenant_id,name,registration_mode,require_target_approval)
VALUES($1,$2,'grant',true) RETURNING id::text`, seed.TenantID, name+" 接收端").Scan(&targetApplication); err != nil {
		return pairResult{}, errors.New("cannot create target development application")
	}
	random := make([]byte, 32)
	if _, err = rand.Read(random); err != nil {
		return pairResult{}, errors.New("cannot create development grant secret")
	}
	targetGrant := "reg_" + base64.RawURLEncoding.EncodeToString(random)
	grantHash := sha256.Sum256([]byte(targetGrant))
	if _, err = pool.Exec(ctx, `INSERT INTO registration_grants(tenant_id,application_id,secret_hash,expires_at)
VALUES($1,$2,$3,clock_timestamp()+interval '30 minutes')`, seed.TenantID, targetApplication, grantHash[:]); err != nil {
		return pairResult{}, errors.New("cannot create target development registration grant")
	}
	source, err := store.Register(ctx, identity.Registration{ApplicationID: seed.ApplicationID, Platform: "linux", InstallationPublicKey: "development-pair-source", RegistrationGrant: seed.RegistrationGrant}, "development-pair-source")
	if err != nil {
		return pairResult{}, err
	}
	target, err := store.Register(ctx, identity.Registration{ApplicationID: targetApplication, Platform: "linux", InstallationPublicKey: "development-pair-target", RegistrationGrant: targetGrant}, "development-pair-target")
	if err != nil {
		return pairResult{}, err
	}
	if _, err = pool.Exec(ctx, `INSERT INTO connection_grants(tenant_id,source_device_id,target_device_id,expires_at,expiry_action,max_sessions)
VALUES($1,$2,$3,clock_timestamp()+interval '30 minutes','terminate',1)`, seed.TenantID, source.DeviceID, target.DeviceID); err != nil {
		return pairResult{}, errors.New("cannot create directional development connection grant")
	}
	return pairResult{
		Source: pairDevice{ApplicationID: seed.ApplicationID, DeviceID: source.DeviceID, DeviceCredential: source.DeviceCredential, ExpiresAt: source.ExpiresAt},
		Target: pairDevice{ApplicationID: targetApplication, DeviceID: target.DeviceID, DeviceCredential: target.DeviceCredential, ExpiresAt: target.ExpiresAt},
	}, nil
}
