// Package adminauth implements explicit self-hosted browser administration.
// No default account, anonymous registration, or service-key-to-browser exchange exists.
package adminauth

import (
	"errors"
	"github.com/alexedwards/argon2id"
	"strings"
	"unicode/utf8"
)

var passwordParams = argon2id.Params{Memory: 64 * 1024, Iterations: 3, Parallelism: 2, SaltLength: 16, KeyLength: 32}

func validPassword(password string) bool {
	return utf8.ValidString(password) && utf8.RuneCountInString(password) >= 15 && len(password) <= 1024 && strings.TrimSpace(password) != "" && !strings.ContainsRune(password, 0)
}
func HashPassword(password string) (string, error) {
	if !validPassword(password) {
		return "", errors.New("password must contain 15 or more characters and at most 1024 UTF-8 bytes")
	}
	return argon2id.CreateHash(password, &passwordParams)
}
func verifyPassword(password, hash string) bool {
	// Bound parameters before a library call allocates memory based on a stored hash.
	if len(password) > 1024 || len(hash) > 256 {
		return false
	}
	params, _, _, err := argon2id.DecodeHash(hash)
	if err != nil || *params != passwordParams {
		return false
	}
	ok, err := argon2id.ComparePasswordAndHash(password, hash)
	return err == nil && ok
}
