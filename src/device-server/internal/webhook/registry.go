// Package webhook implements operator-pinned, tenant-scoped outbound delivery.
// User-controlled URLs never enter an unrestricted HTTP client or DNS resolver.
package webhook

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
)

type Binding struct {
	TenantID  string   `json:"tenant_id"`
	URL       string   `json:"url"`
	SecretRef string   `json:"secret_ref"`
	Secret    string   `json:"secret"`
	Addresses []string `json:"addresses"`
}
type Registry struct{ bindings map[string]Binding }

var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var reference = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var hostname = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)

func (Binding) String() string      { return "[REDACTED webhook binding]" }
func (Binding) GoString() string    { return "[REDACTED webhook binding]" }
func key(tenant, ref string) string { return tenant + "/" + ref }
func Load(path string) (*Registry, error) {
	if path == "" {
		return NewRegistry(nil)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("webhook registry unavailable")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return nil, errors.New("webhook registry too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var bindings []Binding
	if decoder.Decode(&bindings) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("invalid webhook registry")
	}
	return NewRegistry(bindings)
}
func NewRegistry(bindings []Binding) (*Registry, error) {
	if len(bindings) > 256 {
		return nil, errors.New("too many webhook bindings")
	}
	r := &Registry{bindings: make(map[string]Binding)}
	for _, b := range bindings {
		if !uuid.MatchString(b.TenantID) || !reference.MatchString(b.SecretRef) || len(b.Secret) < 32 || len(b.Secret) > 256 || len(b.Addresses) < 1 || len(b.Addresses) > 4 {
			return nil, errors.New("invalid webhook binding")
		}
		for _, v := range []byte(b.Secret) {
			if v < 33 || v > 126 {
				return nil, errors.New("invalid webhook secret")
			}
		}
		u, err := url.Parse(b.URL)
		if err != nil || len(b.URL) > 2048 || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.Port() != "" || !hostname.MatchString(u.Host) || !strings.Contains(u.Host, ".") || strings.Contains(u.Host, "..") || strings.HasSuffix(u.Host, ".") || u.RawPath != "" {
			return nil, errors.New("webhook requires canonical HTTPS hostname URL without port, query or credentials")
		}
		if _, err = netip.ParseAddr(u.Host); err == nil {
			return nil, errors.New("webhook hostname required")
		}
		for _, value := range b.Addresses {
			address, err := netip.ParseAddr(value)
			if err != nil || !publicAddress(address) {
				return nil, errors.New("webhook address must be explicitly approved public IP")
			}
		}
		id := key(b.TenantID, b.SecretRef)
		if _, exists := r.bindings[id]; exists {
			return nil, errors.New("duplicate webhook binding")
		}
		b.Addresses = append([]string(nil), b.Addresses...)
		r.bindings[id] = b
	}
	return r, nil
}
func (r *Registry) lookup(tenant, ref, target string) (Binding, bool) {
	if r == nil {
		return Binding{}, false
	}
	b, ok := r.bindings[key(tenant, ref)]
	return b, ok && b.URL == target
}
func publicAddress(a netip.Addr) bool {
	if !a.IsValid() || a.Zone() != "" || a.Is4In6() || !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	ranges := []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"}
	for _, value := range ranges {
		if netip.MustParsePrefix(value).Contains(a) {
			return false
		}
	}
	return a.Is4() || netip.MustParsePrefix("2000::/3").Contains(a)
}

// Approved exposes no secret material to the management boundary.
func (r *Registry) Approved(tenant, ref, target string) bool {
	_, ok := r.lookup(tenant, ref, target)
	return ok
}

func (Registry) String() string   { return "[REDACTED webhook registry]" }
func (Registry) GoString() string { return "[REDACTED webhook registry]" }
