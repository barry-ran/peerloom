package identity

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestDirectRecoveryKeyCanonicalEncoding(t *testing.T) {
	valid := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if !validDirectKey(valid) {
		t.Fatal("canonical key rejected")
	}
	for _, bad := range []string{"", strings.Repeat("x", 43), valid + "=", strings.Repeat("A", 42) + "B", valid + "\n", strings.Repeat("A", 42) + "+"} {
		if validDirectKey(bad) {
			t.Fatal("noncanonical key accepted")
		}
	}
}
func TestDirectQuotaConfigurationBounds(t *testing.T) {
	if _, err := LoadSettings(func(name string) string {
		if name == "DIRECT_IP_PER_MINUTE" {
			return "0"
		}
		return ""
	}); err == nil {
		t.Fatal("disabled abuse control")
	}
	if _, err := LoadSettings(func(name string) string {
		if name == "DIRECT_APP_DEVICES" {
			return "100001"
		}
		return ""
	}); err == nil {
		t.Fatal("unbounded application quota")
	}
	settings, err := LoadSettings(func(name string) string {
		if name == "DIRECT_APP_PER_DAY" {
			return "25"
		}
		return ""
	})
	if err != nil || settings.DirectAppPerDay != 25 {
		t.Fatal("valid quota override rejected")
	}
}
