package signaling

import (
	"context"
	"errors"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/presence"
	"github.com/coder/websocket"
)

type failingPresence struct {
	testPresence
	faultMu sync.Mutex
	fault   error
}

func (p *failingPresence) Renew(ctx context.Context, tenant, device string, lease presence.Lease) error {
	p.faultMu.Lock()
	fault := p.fault
	p.faultMu.Unlock()
	if fault != nil {
		return fault
	}
	return p.testPresence.Renew(ctx, tenant, device, lease)
}
func TestPresenceFailureCloseClassification(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fault  error
		revoke bool
		want   websocket.StatusCode
	}{
		{"temporary_backend", errors.New("presence unavailable"), false, websocket.StatusInternalError},
		{"fenced_owner", presence.ErrFenced, false, websocket.StatusPolicyViolation},
		{"revoked_credential", nil, true, websocket.StatusPolicyViolation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := &testAuth{}
			store := &failingPresence{}
			server := New(auth, store, nil)
			host := httptest.NewServer(server)
			defer host.Close()
			defer server.Stop()
			conn, ack := connect(t, host.URL)
			defer conn.CloseNow()
			store.faultMu.Lock()
			store.fault = tc.fault
			store.faultMu.Unlock()
			auth.mu.Lock()
			auth.revoked = tc.revoke
			auth.mu.Unlock()
			send(t, conn, message("presence.heartbeat", 1, ack))
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, _, err := conn.Read(ctx)
			if got := websocket.CloseStatus(err); got != tc.want {
				t.Fatalf("close status = %d, want %d", got, tc.want)
			}
		})
	}
}
