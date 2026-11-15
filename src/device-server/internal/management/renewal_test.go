package management

import (
	"bytes"
	"context"
	"testing"
)

func TestServiceReplayUsesStableSubjectButBrowserUsesActor(t *testing.T) {
	p := Principal{tenantID: "tenant", credentialID: "old", subjectID: "old"}
	successor := Principal{tenantID: "tenant", credentialID: "new", subjectID: "old"}
	if !bytes.Equal(aad(p, "op", nil, nil), aad(successor, "op", nil, nil)) {
		t.Fatal("rotation changed replay AAD")
	}
	browser := Principal{tenantID: "tenant", credentialID: "old", browser: &BrowserIdentity{}}
	if bytes.Equal(aad(p, "op", nil, nil), aad(browser, "op", nil, nil)) {
		t.Fatal("browser domain collision")
	}
	if browser.replayID() != "old" {
		t.Fatal("browser actor lost")
	}
}

func TestRenewalRejectsGuessableOperationBeforeDatabase(t *testing.T) {
	s := &Service{}
	_, err := s.RenewServiceKey(context.Background(), Principal{}, "short-op")
	if e, ok := err.(*Error); !ok || e.Code != "IDEMPOTENCY_KEY_REQUIRED" {
		t.Fatal("short operation accepted", err)
	}
}
