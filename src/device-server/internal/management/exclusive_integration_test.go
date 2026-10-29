//go:build integration

package management

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestExclusivePrepareTrustedAtomicReplayAndRead(t *testing.T) {
	f := setup(t)
	pair := makePair(t, f)
	f.service.presence = onlinePresence{}
	yes := true
	_, err := f.service.UpdateApplication(f.ctx, f.principal, pair.actors[1].ApplicationID, ApplicationUpdate{ExclusiveTarget: &yes}, "exclusive-policy-enable")
	if err != nil {
		t.Fatal(err)
	}
	in := ExclusivePrepareInput{SourceDeviceID: pair.actors[0].ID, TargetDeviceID: pair.actors[1].ID, ExpiresInSeconds: 3600}
	value, err := f.service.PrepareExclusiveSession(f.ctx, f.principal, in, "exclusive-preparation-one")
	if err != nil {
		t.Fatal(err)
	}
	replay, err := f.service.PrepareExclusiveSession(f.ctx, f.principal, in, "exclusive-preparation-one")
	if err != nil || replay.ID != value.ID || replay.TargetEpoch != "1" {
		t.Fatalf("replay %v", err)
	}
	view, err := f.service.GetSession(f.ctx, f.principal, value.ID)
	if err != nil || view.TargetEpoch != "1" || view.Prepared == nil || !*view.Prepared {
		t.Fatalf("management projection %v", err)
	}
	page, err := f.service.ListSessions(f.ctx, f.principal, Page{})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("list %v", err)
	}
	changed := in
	changed.ExpiresInSeconds++
	_, err = f.service.PrepareExclusiveSession(f.ctx, f.principal, changed, "exclusive-preparation-one")
	requireCode(t, err, "IDEMPOTENCY_CONFLICT")
	_, err = f.service.TerminateSession(f.ctx, f.principal, value.ID, "exclusive-close-one")
	if err != nil {
		t.Fatal(err)
	}
	replay, err = f.service.PrepareExclusiveSession(f.ctx, f.principal, in, "exclusive-preparation-one")
	if err != nil || replay.State != "closed" || replay.ExclusiveReleaseState != "closing" {
		t.Fatalf("replay revived old snapshot: %v", err)
	}
	var grants, sessions, receipts int
	if err = f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM connection_grants),(SELECT count(*) FROM sessions),(SELECT count(*) FROM exclusive_prepare_requests)`).Scan(&grants, &sessions, &receipts); err != nil || grants != 2 || sessions != 1 || receipts != 1 {
		t.Fatalf("atomic resource counts %d/%d/%d: %v", grants, sessions, receipts, err)
	}
	body, _ := json.Marshal(in)
	request := httptest.NewRequest("POST", "/v1/exclusive-sessions/prepare", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+f.credential.ServiceCredential)
	request.Header.Set("Idempotency-Key", "exclusive-preparation-one")
	response := httptest.NewRecorder()
	NewHandler(f.service).ServeHTTP(response, request)
	if response.Code != 201 {
		t.Fatalf("HTTP prepare replay status %d", response.Code)
	}
}

func TestExclusiveReplayExpiresBeforeSweeperAndOfflineRollsBack(t *testing.T) {
	f := setup(t)
	pair := makePair(t, f)
	yes := true
	if _, err := f.service.UpdateApplication(f.ctx, f.principal, pair.actors[1].ApplicationID, ApplicationUpdate{ExclusiveTarget: &yes}, "expiry-policy-enable"); err != nil {
		t.Fatal(err)
	}
	input := ExclusivePrepareInput{SourceDeviceID: pair.actors[0].ID, TargetDeviceID: pair.actors[1].ID, ExpiresInSeconds: 3600}
	_, err := f.service.PrepareExclusiveSession(f.ctx, f.principal, input, "expiry-prepare-one")
	requireCode(t, err, "PRESENCE_UNAVAILABLE")
	f.service.presence = onlinePresence{}
	value, err := f.service.PrepareExclusiveSession(f.ctx, f.principal, input, "expiry-prepare-one")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE sessions SET connect_deadline=clock_timestamp()-interval '1 second' WHERE id=$1`, value.ID); err != nil {
		t.Fatal(err)
	}
	view, err := f.service.GetSession(f.ctx, f.principal, value.ID)
	if err != nil || view.State != "closed" || view.ExclusiveReleaseState != "closing" {
		t.Fatalf("read did not expose expiry: %v", err)
	}
	replay, err := f.service.PrepareExclusiveSession(f.ctx, f.principal, input, "expiry-prepare-one")
	if err != nil || replay.State != "closed" || replay.ReleaseNotBefore.Before(*value.ReleaseNotBefore) {
		t.Fatalf("expired replay granted old prepared state: %v", err)
	}
	other := input
	other.SourceDeviceID, other.TargetDeviceID = input.TargetDeviceID, input.SourceDeviceID
	_, err = f.service.PrepareExclusiveSession(f.ctx, f.principal, other, "expiry-prepare-one")
	requireCode(t, err, "IDEMPOTENCY_CONFLICT")
	browser := f.principal
	browser.browser = &BrowserIdentity{}
	_, err = f.service.PrepareExclusiveSession(f.ctx, browser, input, "browser-is-not-trusted-service")
	requireCode(t, err, "SERVICE_AUTH_REQUIRED")
}
