package relay

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (*Issuer, Node, []byte) {
	t.Helper()
	secret := []byte(strings.Repeat("test-only-", 4))
	node := Node{TenantID: "tenant-a", URLs: []string{"turn:relay.example.test:3478?transport=udp"}, SecretRef: "tenant-a-key"}
	issuer, err := New(map[string]SecretBinding{node.SecretRef: {TenantID: node.TenantID, Secret: secret, URLs: node.URLs}}, 5*time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	return issuer, node, secret
}
func TestCredentialProtocolExpiryAndRedaction(t *testing.T) {
	issuer, node, key := fixture(t)
	now := time.Unix(1800000000, 123456789)
	c, err := issuer.Issue("tenant-a", "device-sensitive", "session-sensitive", node, now)
	if err != nil {
		t.Fatal(err)
	}
	if !c.ExpiresAt.Equal(now.Truncate(time.Second).Add(5*time.Minute)) || !strings.HasPrefix(c.Username, "1800000300:") {
		t.Fatal("wrong expiry")
	}
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write([]byte(c.Username))
	if c.Credential != base64.StdEncoding.EncodeToString(mac.Sum(nil)) {
		t.Fatal("not coturn REST HMAC-SHA1")
	}
	for _, display := range []string{fmt.Sprint(c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c)} {
		if strings.Contains(display, c.Credential) || strings.Contains(display, c.Username) {
			t.Fatal("secret formatting exposed")
		}
	}
	if strings.Contains(c.Username, "device-sensitive") || strings.Contains(c.Username, "tenant-a") {
		t.Fatal("persistent identity exposed")
	}
	second, err := issuer.Issue("tenant-a", "device-sensitive", "session-sensitive", node, now)
	if err != nil || c.Username == second.Username {
		t.Fatal("nonce not fresh")
	}
	c.URLs[0] = "turn:changed.invalid:3478"
	if node.URLs[0] == c.URLs[0] {
		t.Fatal("returned slice aliases input")
	}
}
func TestScopeAndOperatorEndpointBinding(t *testing.T) {
	issuer, node, _ := fixture(t)
	for name, mutate := range map[string]func(*Node){
		"other tenant":                func(n *Node) { n.TenantID = "tenant-b" },
		"tenant adopts global secret": func(n *Node) { n.TenantID = "" },
		"unknown reference":           func(n *Node) { n.SecretRef = "other" },
		"unapproved endpoint":         func(n *Node) { n.URLs = []string{"turn:attacker.example:3478?transport=udp"} },
		"no endpoint":                 func(n *Node) { n.URLs = nil },
	} {
		t.Run(name, func(t *testing.T) {
			copy := node
			mutate(&copy)
			if _, err := issuer.Issue("tenant-a", "device", "session", copy, time.Now()); err != ErrUnavailable {
				t.Fatal("accepted unauthorized node")
			}
		})
	}
	if _, err := issuer.Issue("tenant-b", "device", "session", node, time.Now()); err != ErrUnavailable {
		t.Fatal("cross tenant")
	}
	global := Node{URLs: []string{"turns:relay.example.test:5349?transport=tcp"}, SecretRef: "global"}
	shared, err := New(map[string]SecretBinding{"global": {Secret: []byte(strings.Repeat("s", 32)), URLs: global.URLs}}, time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = shared.Issue("tenant-a", "device", "session", global, time.Now()); err != nil {
		t.Fatal(err)
	}
	global.TenantID = "tenant-a"
	if _, err = shared.Issue("tenant-a", "device", "session", global, time.Now()); err != ErrUnavailable {
		t.Fatal("tenant adopted shared binding")
	}
}
func TestInputCopiesAndBounds(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	urls := []string{"turn:relay.example:3478"}
	bindings := map[string]SecretBinding{"key": {TenantID: "a", Secret: key, URLs: urls}}
	i, err := New(bindings, time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	key[0] = 'x'
	urls[0] = "turn:changed.example:3478"
	delete(bindings, "key")
	if _, err = i.Issue("a", "d", "s", Node{TenantID: "a", SecretRef: "key", URLs: []string{"turn:relay.example:3478"}}, time.Now()); err != nil {
		t.Fatal("retained mutable config")
	}
	for _, ttl := range []time.Duration{0, 59 * time.Second, 601 * time.Second, time.Minute + time.Nanosecond} {
		if _, err := New(nil, ttl, false); err != ErrConfiguration {
			t.Fatal("invalid TTL accepted")
		}
	}
	if _, err := New(map[string]SecretBinding{"../secret": {Secret: key, URLs: urls}}, time.Minute, false); err != ErrConfiguration {
		t.Fatal("path reference accepted")
	}
}
func TestTURNURLPolicy(t *testing.T) {
	for _, raw := range []string{"turn:relay.example:3478", "turns:relay.example:5349?transport=tcp", "turn:[2001:db8::1]:3478?transport=udp", "turn:10.0.0.1:3478"} {
		if !validURL(raw, false) {
			t.Fatalf("rejected %s", raw)
		}
	}
	for _, raw := range []string{"https://relay.example:443", "turn://host:3478", "turn:user@host:3478", "turn:host:3478/path", "turn:host:3478#fragment", "turn:host:3478?transport=udp&transport=tcp", "turn:host:3478?secret=x", "turns:host:5349?transport=udp", "turn:host:0", "turn:host:65536", "turn:host:03478", "turn:host", "turn:127.0.0.1:3478", "turn:[::]:3478", "turn:224.0.0.1:3478", "turn:localhost:3478", "turn:ho st:3478", "turn:host:3478\n"} {
		if validURL(raw, false) {
			t.Fatalf("accepted %q", raw)
		}
	}
	if !validURL("turn:127.0.0.1:3478", true) {
		t.Fatal("explicit loopback development rejected")
	}
}

func TestConfigurationFormattingRedactsSharedSecret(t *testing.T) {
	issuer, _, secret := fixture(t)
	binding := SecretBinding{Secret: secret}
	for _, value := range []any{issuer, binding, &binding} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			display := fmt.Sprintf(format, value)
			if !strings.Contains(display, "REDACTED") {
				t.Fatal("secret configuration formatter missing")
			}
		}
	}
}

func TestSecretMatchesCoturnTextSemantics(t *testing.T) {
	for _, secret := range []string{strings.Repeat("x", 31) + "\x00", strings.Repeat("x", 31) + "\n", strings.Repeat("x", 31) + "\r", strings.Repeat("x", 31) + " ", strings.Repeat("x", 31) + "中"} {
		_, err := New(map[string]SecretBinding{"key": {Secret: []byte(secret), URLs: []string{"turn:relay.example:3478"}}}, time.Minute, false)
		if err != ErrConfiguration {
			t.Fatal("non-coturn text secret accepted")
		}
	}
}
