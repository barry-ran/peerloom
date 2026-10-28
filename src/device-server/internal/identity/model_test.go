package identity

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validRegistration() Registration {
	return Registration{ApplicationID: "10000000-0000-0000-0000-000000000001", Platform: "linux", InstallationPublicKey: "public-installation-label", RegistrationGrant: "reg_example"}
}

func TestRegistrationValidation(t *testing.T) {
	if err := validRegistration().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Registration){
		"application":  func(r *Registration) { r.ApplicationID = "bad" },
		"platform":     func(r *Registration) { r.Platform = "invalid" },
		"key-empty":    func(r *Registration) { r.InstallationPublicKey = "" },
		"key-large":    func(r *Registration) { r.InstallationPublicKey = strings.Repeat("a", 4097) },
		"no-grant":     func(r *Registration) { r.RegistrationGrant = "" },
		"nested":       func(r *Registration) { r.Metadata = map[string]any{"x": map[string]any{"y": 1}} },
		"array":        func(r *Registration) { r.Metadata = map[string]any{"x": []any{1}} },
		"large-string": func(r *Registration) { r.Metadata = map[string]any{"x": strings.Repeat("a", 1025)} },
	} {
		t.Run(name, func(t *testing.T) {
			r := validRegistration()
			mutate(&r)
			if r.Validate() == nil {
				t.Fatal("accepted invalid input")
			}
		})
	}
}

func TestReplayAADAndKeyIsolation(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	aead, err := newAEAD(key)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize()) // Fixed only for this isolated one-message test.
	aad := replayAAD("registration", "tenant:scope", digest("key"), digest("body"))
	ciphertext := aead.Seal(nil, nonce, []byte("secret"), aad)
	if _, err = aead.Open(nil, nonce, ciphertext, aad); err != nil {
		t.Fatal(err)
	}
	for _, wrong := range [][]byte{
		replayAAD("refresh", "tenant:scope", digest("key"), digest("body")),
		replayAAD("registration", "other-tenant:scope", digest("key"), digest("body")),
		replayAAD("registration", "tenant:scope", digest("different"), digest("body")),
	} {
		if _, err = aead.Open(nil, nonce, ciphertext, wrong); err == nil {
			t.Fatal("AAD mismatch accepted")
		}
	}
	other, _ := newAEAD(bytes.Repeat([]byte{2}, 32))
	if _, err = other.Open(nil, nonce, ciphertext, aad); err == nil {
		t.Fatal("wrong key accepted")
	}
	ciphertext[0] ^= 1
	if _, err = aead.Open(nil, nonce, ciphertext, aad); err == nil {
		t.Fatal("tampering accepted")
	}
}

func TestReplayKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	want := bytes.Repeat([]byte{7}, 32)
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(want)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadReplayKey(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("cannot load encoded key")
	}
	if err = os.WriteFile(path, []byte("invalid secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadReplayKey(path); err == nil || strings.Contains(err.Error(), "invalid secret") {
		t.Fatal("unsafe invalid key handling")
	}
	if _, err = ReadReplayKey(""); err == nil {
		t.Fatal("accepted missing key")
	}
}

func TestSettingsAndIdempotencyBounds(t *testing.T) {
	if err := DefaultSettings().Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSettings(func(k string) string {
		if k == "ROTATION_OVERLAP" {
			return "24h"
		}
		return ""
	}); err == nil {
		t.Fatal("unbounded overlap")
	}
	for _, key := range []string{"", "short", "line\nbreak", strings.Repeat("a", 129)} {
		if validIdempotency(key) {
			t.Fatal("invalid idempotency key accepted")
		}
	}
	if !validIdempotency("request-key-123") {
		t.Fatal("valid key rejected")
	}
}
