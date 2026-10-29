package relay

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRegistryStrictParsingAndEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	config := registryFile{Bindings: map[string]registryEntry{"shared-v1": {Secret: strings.Repeat("a", 32), URLs: []string{"turn:relay.example.com:3478?transport=udp"}}}}
	body, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	issuer, err := LoadIssuer(path, time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	node := Node{SecretRef: "shared-v1", URLs: []string{"turn:relay.example.com:3478?transport=udp"}}
	now := time.Now().UTC()
	issued, err := issuer.Issue("tenant", "device", "session", node, now)
	if err != nil {
		t.Fatal(err)
	}
	derived, err := issuer.Derive("tenant", node, issued.Username, issued.ExpiresAt, now)
	if err != nil || derived.Credential != issued.Credential {
		t.Fatal("persisted username failed to derive")
	}
	offset, err := issuer.Derive("tenant", node, issued.Username, issued.ExpiresAt.In(time.FixedZone("offset", 8*60*60)), now)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := json.Marshal(issued)
	secondJSON, _ := json.Marshal(offset)
	if string(firstJSON) != string(secondJSON) {
		t.Fatal("persisted timezone changed serialized credential response")
	}
	if _, err = issuer.Derive("tenant", node, issued.Username, issued.ExpiresAt.Add(time.Second), now); err == nil {
		t.Fatal("expiry mismatch accepted")
	}
	if _, err = issuer.Derive("tenant", node, issued.Username, issued.ExpiresAt, issued.ExpiresAt); err == nil {
		t.Fatal("expired receipt accepted")
	}
	for _, invalid := range []string{string(body) + "{}", `{"bindings":{},"unknown":true}`, `{"bindings":{"bad":{"tenant_id":"not-uuid","secret":"secret","urls":[]}}}`, strings.Repeat(" ", 128*1024+1)} {
		if err = os.WriteFile(path, []byte(invalid), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = LoadIssuer(path, time.Minute, false); err == nil {
			t.Fatal("invalid registry accepted")
		}
	}
	for _, env := range []map[string]string{{"RELAY_CREDENTIAL_TTL": "30s"}, {"RELAY_DEVELOPMENT_LOOPBACK": "perhaps"}, {"RELAY_DEVICE_ISSUES_PER_MINUTE": "-1"}, {"RELAY_SESSION_ISSUES_PER_MINUTE": "invalid"}} {
		if _, _, err = LoadFromEnvironment(func(key string) string { return env[key] }); err == nil {
			t.Fatal("invalid environment accepted")
		}
	}
	if _, _, err = LoadFromEnvironment(func(string) string { return "" }); err != nil {
		t.Fatal(err)
	}
}
