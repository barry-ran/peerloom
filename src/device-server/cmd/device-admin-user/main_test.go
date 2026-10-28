package main

import (
	"strings"
	"testing"
)

func TestOfflineArguments(t *testing.T) {
	base := "change --offline --tenant-id 11111111-1111-4111-8111-111111111111 --user-id 22222222-2222-4222-8222-222222222222"
	for _, tc := range []struct {
		name, args, input string
		valid             bool
		enabled           int
	}{
		{"enable", base + " --enable", "", true, 1},
		{"disable", base + " --disable", "", true, -1},
		{"role", base + " --scope read", "", true, 0},
		{"reset", base + " --password-stdin", "Synthetic offline password!\r\n", true, 0},
		{"noop", base, "", false, 0},
		{"conflict", base + " --enable --disable", "", false, 0},
		{"bad-role", base + " --scope owner", "", false, 0},
		{"secret-argument", base + " --password SuperSecretValue", "", false, 0},
		{"extra", base + " --enable extra", "", false, 0},
		{"no-offline", "change --tenant-id x --user-id y --enable", "", false, 0},
		{"empty-password", base + " --password-stdin --enable", "", false, 0},
		{"oversized", base + " --password-stdin", strings.Repeat("x", 1027), false, 0},
		{"create", "create --offline --tenant-id x --username owner --scope admin --password-stdin", "Synthetic offline password!", true, 0},
		{"create-enable", "create --offline --tenant-id x --username owner --scope admin --password-stdin --enable", "", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseOptions(strings.Fields(tc.args), strings.NewReader(tc.input))
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
			if err != nil {
				if strings.Contains(err.Error(), "SuperSecretValue") {
					t.Fatal("argument secret leaked")
				}
				return
			}
			if tc.enabled == 0 && got.enabled != nil {
				t.Fatal("unexpected enablement change")
			}
			if tc.enabled != 0 && (got.enabled == nil || *got.enabled != (tc.enabled == 1)) {
				t.Fatal("wrong enablement")
			}
			if tc.name == "reset" && got.password != "Synthetic offline password!" {
				t.Fatal("CRLF was not trimmed")
			}
		})
	}
}
