package main

import "testing"

func TestOfflineAuthorityMustBeExplicit(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"bootstrap", "--tenant-name", "test", "--scope", "admin"},
		{"bootstrap", "--offline", "--tenant-name", "test"},
		{"issue-key", "--offline", "--scope", "admin"},
		{"revoke-key", "--offline", "--tenant-id", "10000000-0000-4000-8000-000000000001"},
	} {
		if err := run(args); err == nil {
			t.Fatal("implicit or underspecified offline authority accepted")
		}
	}
}
