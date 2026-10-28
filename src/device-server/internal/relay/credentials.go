// Package relay implements coturn's documented time-limited REST credentials.
// It does not authenticate callers or deploy a TURN server. The caller must verify
// the device/session immediately before issuing, and enforce independent SDK leases.
// The service must persist/reuse issuance within a bounded generation and limit
// tenant/device/session issuance; a fresh random TURN username is not a quota.
package relay

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // Required by coturn TURN REST authentication, not a password hash.
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var ErrConfiguration = errors.New("invalid relay configuration")
var ErrUnavailable = errors.New("relay unavailable")

// SecretBinding is loaded by the operator, never from a tenant-supplied path.
// Empty TenantID denotes an explicitly shared operator relay. A tenant cannot
// select another tenant's binding merely by knowing its reference. Secret bytes
// are the exact printable ASCII text configured in coturn (for example hex),
// not decoded arbitrary binary: coturn treats its secret as a C string.
type SecretBinding struct {
	TenantID string
	Secret   []byte
	URLs     []string
}

func (SecretBinding) String() string   { return "[REDACTED TURN binding]" }
func (SecretBinding) GoString() string { return "[REDACTED TURN binding]" }

type Node struct {
	TenantID  string
	URLs      []string
	SecretRef string
}

// Credentials are secrets: do not log or include in audit details.
// ExpiresAt limits new TURN authentication, not existing P2P or TURN allocations.
// Device/session revocation is enforced separately by authorization and SDK leases.
// A credential can authenticate other allocations until expiry: TURN REST does not
// cryptographically bind it to a particular PeerConnection or destination peer.
type Credentials struct {
	URLs       []string  `json:"urls"`
	Username   string    `json:"username"`
	Credential string    `json:"credential"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func (Credentials) String() string   { return "[REDACTED TURN credentials]" }
func (Credentials) GoString() string { return "[REDACTED TURN credentials]" }

type Issuer struct {
	bindings            map[string]SecretBinding
	ttl                 time.Duration
	developmentLoopback bool
}

func (*Issuer) String() string   { return "[REDACTED TURN issuer]" }
func (*Issuer) GoString() string { return "[REDACTED TURN issuer]" }

// New copies secrets so later caller mutation cannot redirect or weaken issuance.
// Literal loopback endpoints are forbidden unless enabled for local integration.
// DNS is not resolved here: all endpoints must be operator-approved, including DNS
// ownership and private-network policy. Client ICE gathering performs resolution.
func New(bindings map[string]SecretBinding, ttl time.Duration, developmentLoopback bool) (*Issuer, error) {
	if ttl < time.Minute || ttl > 10*time.Minute || ttl%time.Second != 0 {
		return nil, ErrConfiguration
	}
	copied := make(map[string]SecretBinding, len(bindings))
	for ref, b := range bindings {
		if !validReference(ref) || len(b.Secret) < 32 || len(b.Secret) > 256 || len(b.URLs) < 1 || len(b.URLs) > 4 {
			return nil, ErrConfiguration
		}
		for _, c := range b.Secret {
			if c < 0x21 || c > 0x7e {
				return nil, ErrConfiguration
			}
		}
		for _, u := range b.URLs {
			if !validURL(u, developmentLoopback) {
				return nil, ErrConfiguration
			}
		}
		copied[ref] = SecretBinding{TenantID: b.TenantID, Secret: append([]byte(nil), b.Secret...), URLs: append([]string(nil), b.URLs...)}
	}
	return &Issuer{bindings: copied, ttl: ttl, developmentLoopback: developmentLoopback}, nil
}
func validReference(ref string) bool {
	if len(ref) < 1 || len(ref) > 64 {
		return false
	}
	for _, c := range ref {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// Issue accepts only a previously authorized tenant/device/session. Identity values
// are opaque bounded identifiers; they never become TURN usernames in clear text.
// The shared binding is usable only by a shared node; tenant nodes require an exact
// tenant binding. This prevents tenant node configuration adopting operator secrets.
func (i *Issuer) Issue(tenantID, deviceID, sessionID string, node Node, now time.Time) (Credentials, error) {
	if tenantID == "" || len(tenantID) > 128 || deviceID == "" || len(deviceID) > 128 || sessionID == "" || len(sessionID) > 128 || now.IsZero() {
		return Credentials{}, ErrUnavailable
	}
	if node.TenantID != "" && node.TenantID != tenantID {
		return Credentials{}, ErrUnavailable
	}
	if err := i.ValidateNode(tenantID, node); err != nil {
		return Credentials{}, err
	}
	// The coturn username contains only expiry and a fresh random correlation ID,
	// never a tenant/device/session identifier or the shared secret.
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return Credentials{}, ErrUnavailable
	}
	expires := now.UTC().Truncate(time.Second).Add(i.ttl)
	username := strconv.FormatInt(expires.Unix(), 10) + ":" + base64.RawURLEncoding.EncodeToString(nonce)

	return i.Derive(tenantID, node, username, expires, now)
}

// ValidateNode exposes no secret material and is safe for management admission.
func (i *Issuer) ValidateNode(tenantID string, node Node) error {
	if i == nil || tenantID == "" || (node.TenantID != "" && node.TenantID != tenantID) {
		return ErrUnavailable
	}
	b, ok := i.bindings[node.SecretRef]
	if !ok || b.TenantID != node.TenantID {
		return ErrUnavailable
	}
	if len(node.URLs) < 1 || len(node.URLs) > 4 {
		return ErrUnavailable
	}
	for _, u := range node.URLs {
		allowed := false
		for _, approved := range b.URLs {
			if u == approved {
				allowed = true
				break
			}
		}
		if !allowed || !validURL(u, i.developmentLoopback) {
			return ErrUnavailable
		}
	}
	return nil
}

// Derive reconstructs a persisted issuance only after the caller reauthorizes it.
// The nonce/expiry belong to the server-generated receipt, never client input.
func (i *Issuer) Derive(tenantID string, node Node, username string, expires, now time.Time) (Credentials, error) {
	if err := i.ValidateNode(tenantID, node); err != nil {
		return Credentials{}, err
	}
	timestamp, nonce, ok := strings.Cut(username, ":")
	decoded, err := base64.RawURLEncoding.DecodeString(nonce)
	if !ok || err != nil || len(decoded) != 16 || base64.RawURLEncoding.EncodeToString(decoded) != nonce || timestamp != strconv.FormatInt(expires.Unix(), 10) || !expires.Equal(expires.UTC().Truncate(time.Second)) || !expires.After(now) || expires.After(now.Add(i.ttl)) {
		return Credentials{}, ErrUnavailable
	}
	b := i.bindings[node.SecretRef]
	mac := hmac.New(sha1.New, b.Secret)
	_, _ = mac.Write([]byte(username))
	return Credentials{URLs: append([]string(nil), node.URLs...), Username: username, Credential: base64.StdEncoding.EncodeToString(mac.Sum(nil)), ExpiresAt: expires.UTC()}, nil
}

func validURL(raw string, development bool) bool {
	if len(raw) == 0 || len(raw) > 2048 || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\r\n\t#@/") {
		return false
	}
	scheme, rest, ok := strings.Cut(raw, ":")
	if !ok || (scheme != "turn" && scheme != "turns") {
		return false
	}
	authority, query, _ := strings.Cut(rest, "?")
	if strings.Contains(query, "?") {
		return false
	}
	if query != "" {
		values, err := url.ParseQuery(query)
		if err != nil || len(values) != 1 || len(values["transport"]) != 1 {
			return false
		}
		transport := values.Get("transport")
		if transport != "udp" && transport != "tcp" || scheme == "turns" && transport != "tcp" {
			return false
		}
	}
	host, port, err := net.SplitHostPort(authority)
	if err != nil || host == "" {
		return false
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsUnspecified() && !ip.IsMulticast() && (!ip.IsLoopback() || development)
	}
	if len(host) > 253 || strings.HasSuffix(host, ".") || strings.Contains(host, ":") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return (!strings.EqualFold(host, "localhost") && !strings.HasSuffix(strings.ToLower(host), ".localhost")) || development
}
