package management

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCapacityDefaultsAndLegacyZero(t *testing.T) {
	app, err := normalizeApplication(ApplicationInput{Name: "capacity"})
	if err != nil || *app.MaxConnections != -1 {
		t.Fatal("default must be unlimited", err)
	}
	for _, n := range []int{-1, 0, 1, 1025, 2147483647} {
		app, err = normalizeApplication(ApplicationInput{Name: "capacity", MaxConnections: &n})
		if err != nil || *app.MaxConnections != n {
			t.Fatal("explicit policy changed", n, err)
		}
	}
	for _, n := range []int{-2, 2147483648} {
		if _, err = normalizeApplication(ApplicationInput{Name: "capacity", MaxConnections: &n}); err == nil {
			t.Fatal("unrepresentable policy accepted")
		}
	}
	ttl := 60
	input := ConnectionGrantInput{SourceDeviceID: "00000000-0000-0000-0000-000000000001", TargetDeviceID: "00000000-0000-0000-0000-000000000002", ExpiresInSeconds: &ttl}
	grant, err := normalizeGrant(input)
	if err != nil || *grant.MaxSessions != -1 {
		t.Fatal("omitted grant cap", err)
	}
	for _, n := range []int{-1, 0, 1, 1025} {
		input.MaxSessions = &n
		grant, err = normalizeGrant(input)
		want := n
		if n == 0 {
			want = 1
		}
		if err != nil || *grant.MaxSessions != want {
			t.Fatal("grant policy changed", n, err)
		}
	}
}

func TestGrantJSONOmissionDoesNotConfuseNull(t *testing.T) {
	for _, raw := range []string{`{"max_sessions":null}`, `{"unknown":1}`, `{"max_sessions":"-1"}`} {
		var input ConnectionGrantInput
		if json.Unmarshal([]byte(raw), &input) == nil {
			t.Fatal("invalid policy accepted", raw)
		}
	}
	for _, raw := range []string{`{}`, `{"max_sessions":0}`, `{"max_sessions":-1}`, `{"max_sessions":1025}`} {
		var input ConnectionGrantInput
		if err := json.Unmarshal([]byte(raw), &input); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGrantHTTPDecodeRejectsNullWithoutLosingStrictness(t *testing.T) {
	for _, raw := range []string{`{"max_sessions":null}`, `{"unknown":1}`, `{} {}`} {
		request := httptest.NewRequest("POST", "/", strings.NewReader(raw))
		request.Header.Set("Content-Type", "application/json")
		var input ConnectionGrantInput
		if err := decode(httptest.NewRecorder(), request, &input); err == nil {
			t.Fatal("invalid grant HTTP body accepted", raw)
		}
	}
	for _, raw := range []string{`{}`, `{"max_sessions":0}`, `{"max_sessions":-1}`} {
		request := httptest.NewRequest("POST", "/", strings.NewReader(raw))
		request.Header.Set("Content-Type", "application/json")
		var input ConnectionGrantInput
		if err := decode(httptest.NewRecorder(), request, &input); err != nil {
			t.Fatal(err)
		}
	}
}
