package adminauth

import (
	"fmt"
	"strings"
	"testing"
)

func TestPasswordLibraryPolicyAndBounds(t *testing.T) {
	const password = "This is a test-only passphrase 123!"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if hash == password || !verifyPassword(password, hash) || verifyPassword(password+"wrong", hash) {
		t.Fatal("password library verification failed")
	}
	for _, bad := range []string{"short", strings.Repeat(" ", 20), strings.Repeat("x", 1025), "123456789012345\x00"} {
		if _, err := HashPassword(bad); err == nil {
			t.Fatal("invalid password accepted")
		}
	}
	for _, bad := range []string{"invalid", strings.Replace(hash, "m=65536", "m=4294967295", 1), strings.Replace(hash, "p=2", "p=0", 1)} {
		if verifyPassword(password, bad) {
			t.Fatal("invalid KDF bound accepted")
		}
	}
	if strings.Contains(fmt.Sprintf("%+v", LoginResult{Token: "adm_secret"}), "adm_secret") {
		t.Fatal("session token formatting leaked")
	}
}
