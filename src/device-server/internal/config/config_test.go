package config

import (
	"errors"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	for _, tt := range []struct {
		name      string
		env       map[string]string
		file      string
		wantError bool
	}{
		{"direct", map[string]string{"DATABASE_URL": "postgres://example"}, "", false},
		{"file", map[string]string{"DATABASE_URL_FILE": "secret"}, "postgres://example\n", false},
		{"missing", nil, "", true},
		{"empty-file", map[string]string{"DATABASE_URL_FILE": "secret"}, "", true},
		{"conflict", map[string]string{"DATABASE_URL": "postgres://secret", "DATABASE_URL_FILE": "secret"}, "", true},
		{"address", map[string]string{"DATABASE_URL": "postgres://example", "LISTEN_ADDRESS": "invalid"}, "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, err := LoadWith(func(k string) string { return tt.env[k] }, func(string) ([]byte, error) { return []byte(tt.file), nil })
			if (err != nil) != tt.wantError {
				t.Fatalf("unexpected result: %v", err)
			}
			if err == nil && c.DatabaseURL != "postgres://example" {
				t.Fatal("secret not loaded correctly")
			}
			if err != nil && strings.Contains(err.Error(), "postgres://secret") {
				t.Fatal("secret leaked")
			}
		})
	}
}

func TestReadFailureDoesNotLeakPath(t *testing.T) {
	_, err := LoadWith(func(k string) string {
		if k == "DATABASE_URL_FILE" {
			return "/secret/path"
		}
		return ""
	}, func(string) ([]byte, error) { return nil, errors.New("/secret/path: denied") })
	if err == nil || strings.Contains(err.Error(), "/secret/path") {
		t.Fatal("unsafe error")
	}
}
