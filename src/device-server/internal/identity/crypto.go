package identity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
)

func ReadReplayKey(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("REPLAY_KEY_FILE is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("cannot read REPLAY_KEY_FILE")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(key) != 32 {
		return nil, errors.New("REPLAY_KEY_FILE must contain base64-encoded 32 bytes")
	}
	return key, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("replay key must contain 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func randomToken(prefix string) (string, error) {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(data), nil
}

func digest(value string) []byte {
	hash := sha256.Sum256([]byte(value))
	return hash[:]
}

func replayAAD(operation, scope string, keyHash, requestHash []byte) []byte {
	// JSON arrays are unambiguous: scope separators cannot collide.
	data, _ := json.Marshal([]any{"peerloom-identity-replay-v1", operation, scope, keyHash, requestHash})
	return data
}
