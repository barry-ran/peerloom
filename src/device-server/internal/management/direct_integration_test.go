//go:build integration

package management

import (
	"testing"
	"time"
)

func TestDirectModeExplicitManagementAuthority(t *testing.T) {
	f := setup(t)
	app, err := f.service.CreateApplication(f.ctx, f.principal, ApplicationInput{Name: "default"}, "direct-default-application")
	if err != nil || app.RegistrationMode != "grant" {
		t.Fatal("default registration mode changed")
	}
	direct := "direct"
	change, err := f.service.UpdateApplication(f.ctx, f.principal, app.ID, ApplicationUpdate{RegistrationMode: &direct}, "direct-enable-application")
	if err != nil || change.Application.RegistrationMode != "direct" {
		t.Fatal("explicit direct opt-in failed")
	}
	repeated, err := f.service.UpdateApplication(f.ctx, f.principal, app.ID, ApplicationUpdate{RegistrationMode: &direct}, "direct-enable-application")
	if err != nil || repeated.Application.ID != app.ID {
		t.Fatal("mode change replay failed")
	}
	created, err := f.service.CreateApplication(f.ctx, f.principal, ApplicationInput{Name: "explicit", RegistrationMode: "direct"}, "direct-explicit-application")
	if err != nil || created.RegistrationMode != "direct" {
		t.Fatal("explicit direct create failed")
	}
	otherKey, err := BootstrapKey(f.ctx, f.pool, "foreign", ScopeAdmin, time.Hour, "foreign")
	if err != nil {
		t.Fatal(err)
	}
	other, err := f.service.Authenticate(f.ctx, otherKey.ServiceCredential)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.service.UpdateApplication(f.ctx, other, app.ID, ApplicationUpdate{RegistrationMode: &direct}, "direct-foreign-application")
	requireCode(t, err, "APPLICATION_NOT_FOUND")
	readKey, err := IssueKey(f.ctx, f.pool, f.principal.TenantID(), ScopeRead, time.Hour, "reader")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := f.service.Authenticate(f.ctx, readKey.ServiceCredential)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.service.UpdateApplication(f.ctx, reader, app.ID, ApplicationUpdate{RegistrationMode: &direct}, "direct-reader-application")
	requireCode(t, err, "SCOPE_REQUIRED")
	grant := "grant"
	change, err = f.service.UpdateApplication(f.ctx, f.principal, app.ID, ApplicationUpdate{RegistrationMode: &grant}, "direct-disable-application")
	if err != nil || change.Application.RegistrationMode != "grant" {
		t.Fatal("direct opt-out failed")
	}
}
