package signaling

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/barry-ran/peerloom/src/device-server/internal/authorization"
	"github.com/barry-ran/peerloom/src/device-server/internal/identity"
)

func TestClosedFailureStillDeliversTermination(t *testing.T) {
	session := authorization.Session{ID: uuid(), TenantID: "tenant", SourceDeviceID: "device", TargetDeviceID: "other", State: "closed", CloseReason: "LEASE_EXPIRED"}
	deliveries := closedDeliveries(session, "request")
	if len(deliveries) != 2 {
		t.Fatal("closed state omitted")
	}
	for _, delivery := range deliveries {
		if delivery.Message.Type != "session.terminated" || delivery.Message.SessionID != session.ID || delivery.TenantID != "tenant" {
			t.Fatal("bad termination")
		}
	}
	s := New(&testAuth{}, &testPresence{}, func(_ context.Context, _ identity.Device, e Envelope) ([]Delivery, error) {
		return closedDeliveries(session, e.ID), errors.New("denied")
	})
	h := httptest.NewServer(s)
	defer h.Close()
	defer s.Stop()
	c, ack := connect(t, h.URL)
	defer c.CloseNow()
	send(t, c, message("session.renew", 1, ack))
	if e := receive(t, c); e.Type != "session.terminated" {
		t.Fatalf("missing termination: %s", e.Type)
	}
	if e := receive(t, c); e.Type != "error" {
		t.Fatalf("missing request error: %s", e.Type)
	}
}
func TestDuplicateIDWithNewSequenceIsRejected(t *testing.T) {
	s := New(&testAuth{}, &testPresence{}, nil)
	h := httptest.NewServer(s)
	defer h.Close()
	defer s.Stop()
	c, ack := connect(t, h.URL)
	defer c.CloseNow()
	e := message("presence.heartbeat", 1, ack)
	send(t, c, e)
	receive(t, c)
	e.Seq = 2
	send(t, c, e)
	requireSocketClosed(t, c)
}
func TestClosedDeliveryDoesNotInventSession(t *testing.T) {
	if closedDeliveries(authorization.Session{}, "request") != nil {
		t.Fatal("invented closure")
	}
}
