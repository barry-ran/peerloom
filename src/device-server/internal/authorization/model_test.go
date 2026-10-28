package authorization

import (
	"testing"
	"time"
)

func TestLeaseAndGrantSemantics(t *testing.T) {
	at := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	g := grant{expires: at.Add(5 * time.Second), action: "terminate"}
	if got := leaseDeadline(g, at, time.Minute); got != g.expires {
		t.Fatal("terminate lease outlives grant")
	}
	g.action = "no_new_connections"
	if got := leaseDeadline(g, at, time.Minute); got != at.Add(time.Minute) {
		t.Fatal("existing session lease unnecessarily capped")
	}
	g.expires = at.Add(-time.Second)
	if grantValid(g, Session{State: "connected"}, at) != nil {
		t.Fatal("existing no-new-connections session rejected")
	}
	if grantValid(g, Session{State: "authorizing"}, at) == nil {
		t.Fatal("expired grant accepted new connection")
	}
	g.revoked = &at
	if grantValid(g, Session{State: "connected"}, at) == nil {
		t.Fatal("revocation bypassed")
	}
	if DefaultOptions().validate() != nil {
		t.Fatal("defaults invalid")
	}
	if (Options{LeaseTTL: time.Hour, ApprovalTimeout: time.Second}).validate() == nil {
		t.Fatal("unbounded lease accepted")
	}
}
