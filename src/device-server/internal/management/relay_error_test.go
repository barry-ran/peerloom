package management

import (
	"encoding/json"
	"github.com/barry-ran/peerloom/src/device-server/internal/relay"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRelayValidationHTTPStatusIsSafe(t *testing.T) {
	valid := RelayNodeInput{Name: "relay", Endpoint: "turn:relay.example.com:3478?transport=udp", Secret: strings.Repeat("s", 32)}
	for _, tc := range []struct {
		key    []byte
		input  RelayNodeInput
		status int
		code   string
	}{
		{nil, valid, 503, "RELAY_CONFIGURATION_UNAVAILABLE"},
		{[]byte(strings.Repeat("k", 32)), RelayNodeInput{Name: "relay", Endpoint: valid.Endpoint, Secret: "private-invalid-secret"}, 422, "INVALID_RELAY_NODE"},
	} {
		issuer, err := relay.NewDatabaseIssuer(tc.key, 5*time.Minute, false)
		if err != nil {
			t.Fatal(err)
		}
		s := &Service{relayIssuer: issuer}
		err = s.validateRelay("tenant", tc.input)
		recorder := httptest.NewRecorder()
		writeError(recorder, "request", err)
		if recorder.Code != tc.status || !strings.Contains(recorder.Body.String(), tc.code) {
			t.Fatal("relay error mapping failed")
		}
		if strings.Contains(recorder.Body.String(), tc.input.Secret) {
			t.Fatal("validation leaked secret")
		}
	}
	body, _ := json.Marshal(RelayNode{HasSecret: true, SecretVersion: 2})
	if strings.Contains(string(body), strings.Repeat("s", 32)) {
		t.Fatal("secret in response")
	}
}
