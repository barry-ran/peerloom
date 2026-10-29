package identity

import (
	"context"
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
	names := []string{"DIRECT_GLOBAL_PER_MINUTE", "DIRECT_IP_PER_MINUTE", "DIRECT_APP_PER_MINUTE", "DIRECT_APP_PER_DAY", "DIRECT_APP_DEVICES"}
	defaults := DefaultSettings()
	if defaults.DirectGlobalPerMinute != 0 || defaults.DirectIPPerMinute != 0 || defaults.DirectAppPerMinute != 0 || defaults.DirectAppPerDay != 0 || defaults.DirectAppDevices != 0 {
		t.Fatal("direct policy defaults must be unlimited")
	}
	for _, name := range names {
		for _, value := range []string{"0", "1", "100001", "2147483647"} {
			if _, err := LoadSettings(func(key string) string {
				if key == name {
					return value
				}
				return ""
			}); err != nil {
				t.Fatalf("valid %s=%s: %v", name, value, err)
			}
		}
		for _, value := range []string{"-1", "2147483648", "999999999999999999999999", "bad"} {
			if _, err := LoadSettings(func(key string) string {
				if key == name {
					return value
				}
				return ""
			}); err == nil {
				t.Fatalf("invalid %s=%s accepted", name, value)
			}
		}
	}
}
func TestDisabledDirectBucketsNeedNoDatabase(t *testing.T) {
	// A nil pool would panic if zero policies performed even an empty transaction.
	s := &Store{settings: DefaultSettings()}
	if err := s.directAdmission(context.Background(), []directBucket{{"global", 0}, {"ip:192.0.2.1", 0}}); err != nil {
		t.Fatal(err)
	}
}
