package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestExclusiveSecretOutput(t *testing.T) {
	p := filepath.Join(t.TempDir(), "connection.json")
	f, err := exclusiveOutput(p)
	if err != nil {
		t.Fatal(err)
	}
	if err = writeSecret(f, map[string]string{"service_credential": "test-only"}); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if f, err = exclusiveOutput(p); err == nil {
		f.Close()
		t.Fatal("overwrote secret")
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), "test-only") {
		t.Fatal("missing data")
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(p)
		if st.Mode().Perm() != 0600 {
			t.Fatal("unsafe permissions")
		}
	}
	if _, err = exclusiveOutput(""); err == nil {
		t.Fatal("empty path accepted")
	}
}
func TestSetupRequiresExplicitAuthorityAndOutput(t *testing.T) {
	for _, args := range [][]string{{}, {"--tenant-name", "t", "--application-name", "a", "--output", "x"}, {"--offline", "--tenant-name", "t", "--application-name", "a"}, {"--offline", "--tenant-name", "t", "--application-name", "a", "--output", "x", "--ttl", "0"}} {
		if err := runSetup(args); err == nil {
			t.Fatal("invalid setup accepted")
		}
	}
}
func TestSetupReadBounds(t *testing.T) {
	p := filepath.Join(t.TempDir(), "material.json")
	if err := os.WriteFile(p, []byte(strings.Repeat("x", 16385)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSetup(p); err == nil {
		t.Fatal("oversized input accepted")
	}
	if err := os.WriteFile(p, []byte(`{"service_credential":"test"} trailing`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSetup(p); err == nil {
		t.Fatal("trailing JSON accepted")
	}
}
