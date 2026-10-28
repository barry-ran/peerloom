//go:build integration

package management

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

func TestConnectionGrantAbsoluteExpiryAndStableReplay(t *testing.T) {
	f := setup(t)
	pair := makePair(t, f)
	var now time.Time
	if err := f.pool.QueryRow(f.ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		t.Fatal(err)
	}
	absolute := now.Add(time.Hour)
	input := ConnectionGrantInput{SourceDeviceID: pair.actors[0].ID, TargetDeviceID: pair.actors[1].ID, ExpiresAt: &absolute}
	result, err := f.service.CreateConnectionGrant(f.ctx, f.principal, input, "absolute-expiry-grant")
	if err != nil || !result.ExpiresAt.Equal(absolute.Truncate(time.Microsecond)) {
		t.Fatalf("absolute expiry not preserved: %v", err)
	}
	offset := absolute.In(time.FixedZone("UTC+8", 8*3600))
	input.ExpiresAt = &offset
	replay, err := f.service.CreateConnectionGrant(f.ctx, f.principal, input, "absolute-expiry-grant")
	if err != nil || replay.ID != result.ID {
		t.Fatalf("equivalent offset changed replay fingerprint: %v", err)
	}
	input.ExpiresInSeconds = ptr(60)
	_, err = f.service.CreateConnectionGrant(f.ctx, f.principal, input, "ambiguous-expiry-grant")
	requireCode(t, err, "AMBIGUOUS_GRANT_EXPIRY")
	input.ExpiresInSeconds = nil
	expired := now.Add(-time.Second)
	input.ExpiresAt = &expired
	_, err = f.service.CreateConnectionGrant(f.ctx, f.principal, input, "expired-absolute-grant")
	requireCode(t, err, "INVALID_GRANT_TTL")
	tooFar := now.Add(31 * 24 * time.Hour)
	input.ExpiresAt = &tooFar
	_, err = f.service.CreateConnectionGrant(f.ctx, f.principal, input, "far-future-absolute-grant")
	requireCode(t, err, "INVALID_GRANT_TTL")

	// Receipt replay preserves the original issuance result even after the
	// authorization itself expires; it does not extend or recreate the grant.
	if err = f.pool.QueryRow(f.ctx, "SELECT clock_timestamp()+interval '1 second'").Scan(&absolute); err != nil {
		t.Fatal(err)
	}
	input.ExpiresAt = &absolute
	soon, err := f.service.CreateConnectionGrant(f.ctx, f.principal, input, "short-absolute-replay")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(f.ctx, "SELECT pg_sleep(1.1)"); err != nil {
		t.Fatal(err)
	}
	replay, err = f.service.CreateConnectionGrant(f.ctx, f.principal, input, "short-absolute-replay")
	if err != nil || replay.ID != soon.ID || !replay.ExpiresAt.Equal(soon.ExpiresAt) {
		t.Fatalf("expired issuance replay recreated or rejected receipt: %v", err)
	}

	// HTTP parses RFC3339 offsets, rejects malformed dates and both expiry modes.
	handler := NewHandler(f.service)
	call := func(expiry any, relative any, key string) int {
		value := map[string]any{"source_device_id": pair.actors[0].ID, "target_device_id": pair.actors[1].ID, "expires_at": expiry}
		if relative != nil {
			value["expires_in_seconds"] = relative
		}
		body, _ := json.Marshal(value)
		request := httptest.NewRequest("POST", "/v1/connection-grants", bytes.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+f.credential.ServiceCredential)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", key)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response.Code
	}
	if status := call(offset.Format(time.RFC3339), nil, "http-offset-expiry"); status != 201 {
		t.Fatalf("offset timestamp status=%d", status)
	}
	if status := call("not-a-time", nil, "http-invalid-expiry"); status != 422 {
		t.Fatalf("invalid timestamp status=%d", status)
	}
	if status := call(offset.Format(time.RFC3339), 0, "http-both-expiry-zero"); status != 422 {
		t.Fatalf("both fields including relative zero status=%d", status)
	}
}
