package management

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestInputAndAuthorityBounds(t *testing.T) {
	if DefaultSettings().validate() != nil {
		t.Fatal("invalid default replay settings")
	}
	if validateKey(Scope("owner"), time.Hour, "label") == nil {
		t.Fatal("unsupported scope accepted")
	}
	if validateKey(ScopeAdmin, 365*24*time.Hour, "label") == nil {
		t.Fatal("unbounded key lifetime")
	}
	if _, err := normalizeApplication(ApplicationInput{Name: "test", RegistrationMode: "both"}); err == nil {
		t.Fatal("unsupported combined mode enabled")
	}
	if _, err := normalizeApplication(ApplicationInput{Name: "test\x00"}); err == nil {
		t.Fatal("NUL text accepted")
	}
	s := &Service{}
	for _, credential := range []string{"", "dev_" + strings.Repeat("a", 43), "reg_" + strings.Repeat("a", 43)} {
		if _, err := s.Authenticate(context.Background(), credential); err == nil {
			t.Fatal("wrong audience accepted")
		}
	}
}

func TestCursorIsNotTenantAuthority(t *testing.T) {
	p := Principal{tenantID: "10000000-0000-4000-8000-000000000001"}
	cursor := encodeCursor(p, "applications", time.Now().UTC(), "20000000-0000-4000-8000-000000000001")
	if _, _, err := parsePage(p, Page{Cursor: cursor}, "applications"); err != nil {
		t.Fatal(err)
	}
	other := Principal{tenantID: "10000000-0000-4000-8000-000000000002"}
	if _, _, err := parsePage(other, Page{Cursor: cursor}, "applications"); err == nil {
		t.Fatal("cross-tenant cursor accepted")
	}
	data, _ := base64.RawURLEncoding.DecodeString(cursor)
	bad := base64.RawURLEncoding.EncodeToString(append(data, []byte(" {}")...))
	if _, _, err := parsePage(p, Page{Cursor: bad}, "applications"); err == nil {
		t.Fatal("cursor trailing data accepted")
	}
	if _, _, err := parsePage(p, Page{Limit: 101}, "applications"); err == nil {
		t.Fatal("unbounded page")
	}
}

func TestGrantAndDeviceInputBounds(t *testing.T) {
	ttl := 60
	input := ConnectionGrantInput{SourceDeviceID: "00000000-0000-0000-0000-000000000001", TargetDeviceID: "00000000-0000-0000-0000-000000000002", ExpiresInSeconds: &ttl}
	normalized, err := normalizeGrant(input)
	if err != nil || normalized.MaxSessions != 1 || normalized.ExpiryAction != "terminate" {
		t.Fatalf("safe defaults: %+v %v", normalized, err)
	}
	input.TargetDeviceID = input.SourceDeviceID
	if _, err = normalizeGrant(input); err == nil {
		t.Fatal("self-grant accepted")
	}
	if validProperties(map[string]any{"nested": map[string]any{"value": true}}) {
		t.Fatal("nested metadata accepted")
	}
	if validProperties(map[string]any{"null\x00": true}) {
		t.Fatal("NUL metadata key accepted")
	}
}
