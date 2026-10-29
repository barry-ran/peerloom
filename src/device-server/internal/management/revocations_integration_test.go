//go:build integration

package management

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/barry-ran/peerloom/src/device-server/internal/authorization"
	"github.com/barry-ran/peerloom/src/device-server/internal/identity"
)

type onlinePresence struct{}

func (onlinePresence) Online(context.Context, string, string) (bool, error) { return true, nil }

type devicePair struct {
	store       *identity.Store
	auth        *authorization.Service
	credentials []identity.Credential
	actors      []identity.Device
	grant       ConnectionGrant
}

func makePair(t *testing.T, f fixture) devicePair {
	t.Helper()
	store, err := identity.New(f.pool, f.key)
	if err != nil {
		t.Fatal(err)
	}
	result := devicePair{store: store}
	for i := 0; i < 2; i++ {
		app, err := f.service.CreateApplication(f.ctx, f.principal, ApplicationInput{Name: fmt.Sprintf("pair-%d", i)}, fmt.Sprintf("pair-app-%d", i))
		if err != nil {
			t.Fatal(err)
		}
		grant, err := f.service.IssueRegistrationGrant(f.ctx, f.principal, RegistrationGrantInput{ApplicationID: app.ID}, fmt.Sprintf("pair-reg-%d", i))
		if err != nil {
			t.Fatal(err)
		}
		credential, err := store.Register(f.ctx, identity.Registration{ApplicationID: app.ID, Platform: "linux", InstallationPublicKey: fmt.Sprintf("pair-install-%d", i), RegistrationGrant: grant.Grant}, fmt.Sprintf("pair-register-%d", i))
		if err != nil {
			t.Fatal(err)
		}
		actor, err := store.Authenticate(f.ctx, credential.DeviceCredential)
		if err != nil {
			t.Fatal(err)
		}
		result.credentials = append(result.credentials, credential)
		result.actors = append(result.actors, actor)
	}
	result.grant, err = f.service.CreateConnectionGrant(f.ctx, f.principal, ConnectionGrantInput{SourceDeviceID: result.actors[0].ID, TargetDeviceID: result.actors[1].ID, ExpiresInSeconds: ptr(300), MaxSessions: ptr(10)}, "pair-connection-grant")
	if err != nil {
		t.Fatal(err)
	}
	result.auth, err = authorization.New(f.pool, onlinePresence{}, authorization.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestManagementDeviceRevocationSerializesRefreshRequestAndRenew(t *testing.T) {
	f := setup(t)
	pair := makePair(t, f)
	session, err := pair.auth.Request(f.ctx, pair.actors[0], pair.actors[1].ID, "00000000-0000-0000-0000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	var refreshed identity.Credential
	var refreshErr, errorRevoke error
	var result Revocation
	wg.Add(4)
	go func() {
		defer wg.Done()
		<-start
		refreshed, refreshErr = pair.store.Refresh(f.ctx, pair.credentials[0].DeviceCredential, "concurrent-refresh")
	}()
	go func() {
		defer wg.Done()
		<-start
		result, errorRevoke = f.service.RevokeDevice(f.ctx, f.principal, pair.actors[0].ID, "concurrent-revoke")
	}()
	go func() {
		defer wg.Done()
		<-start
		_, _ = pair.auth.Request(f.ctx, pair.actors[0], pair.actors[1].ID, "00000000-0000-0000-0000-000000000002")
	}()
	go func() {
		defer wg.Done()
		<-start
		_, _ = pair.auth.Renew(f.ctx, pair.actors[1], session.ID)
	}()
	close(start)
	wg.Wait()
	if errorRevoke != nil || !result.Revoked {
		t.Fatalf("revocation failed: %v", errorRevoke)
	}
	if _, err = pair.store.Authenticate(f.ctx, pair.credentials[0].DeviceCredential); err == nil {
		t.Fatal("old credential survived revocation")
	}
	if refreshErr == nil {
		if _, err = pair.store.Authenticate(f.ctx, refreshed.DeviceCredential); err == nil {
			t.Fatal("concurrent refreshed credential survived revocation")
		}
	}
	var active int
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM sessions WHERE tenant_id=$1 AND state<>'closed'", f.principal.TenantID()).Scan(&active); err != nil || active != 0 {
		t.Fatalf("active sessions survived: %d %v", active, err)
	}
	replay, err := f.service.RevokeDevice(f.ctx, f.principal, pair.actors[0].ID, "concurrent-revoke")
	if err != nil || replay.ID != result.ID {
		t.Fatalf("revocation replay: %v", err)
	}
}

func TestManagementGrantRevocationAndSessionTermination(t *testing.T) {
	f := setup(t)
	pair := makePair(t, f)
	session, err := pair.auth.Request(f.ctx, pair.actors[0], pair.actors[1].ID, "00000000-0000-0000-0000-000000000003")
	if err != nil {
		t.Fatal(err)
	}
	closed, err := f.service.TerminateSession(f.ctx, f.principal, session.ID, "admin-terminate-session")
	if err != nil || closed.State != "closed" || closed.CloseReason != "ADMIN_TERMINATED" {
		t.Fatalf("terminate: %+v %v", closed, err)
	}
	session, err = pair.auth.Request(f.ctx, pair.actors[0], pair.actors[1].ID, "00000000-0000-0000-0000-000000000004")
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.service.RevokeConnectionGrant(f.ctx, f.principal, pair.grant.ID, "admin-revoke-grant")
	if err != nil || len(result.Sessions) != 1 || result.Sessions[0].ID != session.ID {
		t.Fatalf("revoke: %+v %v", result, err)
	}
	if _, err = pair.auth.Request(f.ctx, pair.actors[0], pair.actors[1].ID, "00000000-0000-0000-0000-000000000005"); err == nil {
		t.Fatal("revoked grant admitted a new session")
	}
	device, err := f.service.UpdateDevice(f.ctx, f.principal, pair.actors[0].ID, DeviceUpdate{DisplayName: ptr("新名称"), Connectable: ptr(false), Tags: ptr(map[string]any{"owner": "研发"})}, "update-device-properties")
	if err != nil || device.Connectable || device.Online != nil {
		t.Fatalf("typed device update: %+v %v", device, err)
	}
	otherKey, err := BootstrapKey(f.ctx, f.pool, "other", ScopeAdmin, DefaultSettings().ReceiptTTL, "other")
	if err != nil {
		t.Fatal(err)
	}
	other, err := f.service.Authenticate(f.ctx, otherKey.ServiceCredential)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.service.RevokeDevice(f.ctx, other, device.ID, "cross-tenant-device")
	requireCode(t, err, "DEVICE_NOT_FOUND")
	_, err = f.service.GetConnectionGrant(f.ctx, other, pair.grant.ID)
	requireCode(t, err, "GRANT_NOT_FOUND")
	_, err = f.service.RevokeConnectionGrant(f.ctx, other, pair.grant.ID, "foreign-grant-revoke")
	requireCode(t, err, "GRANT_NOT_FOUND")
	_, err = f.service.RevokeConnectionGrant(f.ctx, f.principal, "00000000-0000-0000-0000-000000000099", "missing-grant-revoke")
	requireCode(t, err, "GRANT_NOT_FOUND")
	_, err = f.service.TerminateSession(f.ctx, other, session.ID, "foreign-session-terminate")
	requireCode(t, err, "SESSION_NOT_FOUND")
	_, err = f.service.CreateConnectionGrant(f.ctx, other, ConnectionGrantInput{SourceDeviceID: pair.actors[0].ID, TargetDeviceID: pair.actors[1].ID, ExpiresInSeconds: ptr(60)}, "cross-tenant-create")
	requireCode(t, err, "DEVICE_NOT_FOUND")
}

func ptr[T any](value T) *T { return &value }
