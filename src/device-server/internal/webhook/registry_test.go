package webhook

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func goodBinding() Binding {
	return Binding{TenantID: "00000000-0000-4000-8000-000000000001", URL: "https://hooks.example.com/peerloom", SecretRef: "tenant1", Secret: strings.Repeat("x", 32), Addresses: []string{"8.8.8.8"}}
}
func TestRegistryBindingAndRedaction(t *testing.T) {
	b := goodBinding()
	r, err := NewRegistry([]Binding{b})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.lookup(b.TenantID, b.SecretRef, b.URL); !ok {
		t.Fatal("approved binding missing")
	}
	for _, v := range [][3]string{{"00000000-0000-4000-8000-000000000002", b.SecretRef, b.URL}, {b.TenantID, "other", b.URL}, {b.TenantID, b.SecretRef, b.URL + "/other"}} {
		if _, ok := r.lookup(v[0], v[1], v[2]); ok {
			t.Fatal("binding crossed")
		}
	}
	if strings.Contains(fmt.Sprintf("%v %+v %#v", b, b, b), b.Secret) {
		t.Fatal("secret formatting leak")
	}
	b.Addresses[0] = "127.0.0.1"
	saved, _ := r.lookup(b.TenantID, b.SecretRef, b.URL)
	if saved.Addresses[0] != "8.8.8.8" {
		t.Fatal("caller changed registry")
	}
}
func TestRegistryRejectsUnsafeTargets(t *testing.T) {
	for _, target := range []string{"http://hooks.example.com/a", "https://127.0.0.1/a", "https://user:pass@hooks.example.com/a", "https://hooks.example.com:443/a", "https://hooks.example.com/a?token=secret", "https://hooks.example.com/a#x", "https://hooks.example.com./a", "https://hooks.example.com/a%2fb"} {
		t.Run(target, func(t *testing.T) {
			b := goodBinding()
			b.URL = target
			if _, err := NewRegistry([]Binding{b}); err == nil {
				t.Fatal("unsafe URL accepted")
			}
		})
	}
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.100.100.200", "::1", "::ffff:8.8.8.8", "fe80::1%eth0", "fc00::1", "2001:db8::1", "3fff::1", "198.18.0.1", "192.0.2.1", "0.0.0.0", "255.255.255.255"} {
		a, err := netip.ParseAddr(ip)
		if err == nil && publicAddress(a) {
			t.Fatalf("special address accepted: %s", ip)
		}
	}
}
func TestSignatureBindsIdentityTimestampAndBody(t *testing.T) {
	a := signature("secret", "id", "123", []byte("body"))
	for _, b := range []string{signature("other", "id", "123", []byte("body")), signature("secret", "other", "123", []byte("body")), signature("secret", "id", "124", []byte("body")), signature("secret", "id", "123", []byte("different"))} {
		if a == b {
			t.Fatal("signature binding missing")
		}
	}
	if len(a) != 67 || !strings.HasPrefix(a, "v1=") {
		t.Fatal("signature shape")
	}
}

func TestOwnerFormattingRedactsNestedSecrets(t *testing.T) {
	b := goodBinding()
	r, err := NewRegistry([]Binding{b})
	if err != nil {
		t.Fatal(err)
	}
	sender := NewSender(r)
	worker := &Worker{sender: sender}
	for _, value := range []any{r, *r, sender, *sender, worker, *worker} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(format, value), b.Secret) {
				t.Fatalf("secret exposed by %T / %s", value, format)
			}
		}
	}
}
