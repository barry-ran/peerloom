//go:build integration

package relay

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This fixture bridge is only enabled by the isolated real-coturn harness. It is
// not a production credential endpoint and never prints secret material.
func TestEmitLocalTURNFixture(t *testing.T) {
	directory := os.Getenv("TEST_RELAY_FIXTURE_DIRECTORY")
	if directory == "" {
		t.Skip("requires isolated local TURN fixture directory")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("private fixture directory required")
	}
	path := filepath.Join(directory, "shared-secret")
	info, err = os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("private fixture secret required")
	}
	secret, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read fixture secret")
	}
	url := "turn:127.0.0.1:53478?transport=udp"
	issuer, err := New(map[string]SecretBinding{"test": {Secret: secret, URLs: []string{url}}}, time.Minute, true)
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := issuer.Issue("test-tenant", "test-device", "test-session", Node{URLs: []string{url}, SecretRef: "test"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for name, at := range map[string]time.Time{"credentials.json": time.Now(), "expired.json": time.Now().Add(-2 * time.Minute), "soon.json": time.Now().Add(-52 * time.Second)} {
		credentials, err = issuer.Issue("test-tenant", "test-device", "test-session", Node{URLs: []string{url}, SecretRef: "test"}, at)
		if err != nil {
			t.Fatal(err)
		}
		output, err := os.OpenFile(filepath.Join(directory, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal("exclusive fixture output")
		}
		err = json.NewEncoder(output).Encode(credentials)
		closeErr := output.Close()
		if err != nil || closeErr != nil {
			t.Fatal("write fixture credentials")
		}
		for extension, value := range map[string]string{"username": credentials.Username, "credential": credentials.Credential} {
			file, err := os.OpenFile(filepath.Join(directory, strings.TrimSuffix(name, ".json")+"."+extension), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				t.Fatal("exclusive fixture text output")
			}
			_, err = file.WriteString(value)
			closeErr := file.Close()
			if err != nil || closeErr != nil {
				t.Fatal("write fixture text")
			}
		}

	}
}
