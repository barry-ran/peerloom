package relay

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEncryptionKeyExactBytesAndNoRegistryFallback(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "key")
	key := bytes.Repeat([]byte{0}, 32)
	key[0] = '\n'
	key[31] = ' '
	if err := os.WriteFile(file, key, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := loadEncryptionKey(file)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatal("raw key changed")
	}
	i, err := NewDatabaseIssuer(got, time.Minute, false)
	if err != nil || len(i.keyID) != 64 {
		t.Fatal("valid raw key rejected")
	}
	for _, size := range []int{0, 31, 33} {
		if err := os.WriteFile(file, make([]byte, size), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadEncryptionKey(file); err == nil {
			t.Fatal("wrong key length accepted")
		}
	}
	if _, _, err := LoadFromEnvironment(func(k string) string {
		if k == "RELAY_REGISTRY_FILE" {
			return "legacy.json"
		}
		return ""
	}); err == nil {
		t.Fatal("legacy registry silently used")
	}
}
func TestSecretAEADBindingAndWriteValidation(t *testing.T) {
	i, err := NewDatabaseIssuer(bytes.Repeat([]byte{7}, 32), time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{'s'}, 32)
	nonce := make([]byte, i.aead.NonceSize())
	aad := secretAAD("node", "tenant", i.keyID, 1)
	ciphertext := i.aead.Seal(nil, nonce, secret, aad)
	if bytes.Contains(ciphertext, secret) {
		t.Fatal("plaintext persisted")
	}
	for _, wrong := range [][]byte{secretAAD("other", "tenant", i.keyID, 1), secretAAD("node", "other", i.keyID, 1), secretAAD("node", "tenant", i.keyID, 2), secretAAD("node", "tenant", "other", 1)} {
		if _, err := i.aead.Open(nil, nonce, ciphertext, wrong); err == nil {
			t.Fatal("AAD scope change accepted")
		}
	}
	for _, s := range []string{"", string(bytes.Repeat([]byte{'x'}, 31)), string(bytes.Repeat([]byte{'x'}, 257)), string(secret) + "\n"} {
		if err := i.ValidateConfiguration("turn:relay.example.com:3478?transport=udp", s); err == nil {
			t.Fatal("invalid secret accepted")
		}
	}
}
