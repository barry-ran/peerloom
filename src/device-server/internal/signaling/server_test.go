package signaling

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/identity"
	"github.com/barry-ran/peerloom/src/device-server/internal/presence"
	"github.com/coder/websocket"
)

type testAuth struct {
	mu      sync.Mutex
	revoked bool
}

func (a *testAuth) Authenticate(_ context.Context, token string) (identity.Device, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.revoked || token != "dev_test" {
		return identity.Device{}, errors.New("denied")
	}
	return identity.Device{ID: "device", TenantID: "tenant"}, nil
}

type testPresence struct {
	mu      sync.Mutex
	current presence.Lease
}

func (p *testPresence) Claim(context.Context, string, string) (presence.Lease, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.current = presence.Lease{Generation: p.current.Generation + 1, Token: uuid()}
	return p.current, nil
}
func (p *testPresence) Renew(_ context.Context, _, _ string, l presence.Lease) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if l != p.current {
		return presence.ErrFenced
	}
	return nil
}
func (p *testPresence) Release(_ context.Context, _, _ string, l presence.Lease) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if l == p.current {
		p.current.Token = ""
	}
	return nil
}
func message(kind string, seq int64, lease Envelope) Envelope {
	return Envelope{Version: 1, Type: kind, ID: uuid(), Seq: seq, SentAt: time.Now().UTC().Format(time.RFC3339Nano), Generation: lease.Generation, Fence: lease.Fence, Payload: json.RawMessage(`{}`)}
}
func send(t *testing.T, c *websocket.Conn, e Envelope) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	b, _ := json.Marshal(e)
	if err := c.Write(ctx, websocket.MessageText, b); err != nil {
		t.Fatal(err)
	}
}
func receive(t *testing.T, c *websocket.Conn) Envelope {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, b, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	e, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func connect(t *testing.T, url string) (*websocket.Conn, Envelope) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(url, "http"), &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer dev_test"}}})
	if err != nil {
		t.Fatal(err)
	}
	send(t, c, message("hello", 0, Envelope{}))
	ack := receive(t, c)
	if ack.Type != "hello.ack" || ack.Generation == 0 || ack.Fence == "" {
		t.Fatalf("bad ack %#v", ack)
	}
	return c, ack
}
func assertClosed(t *testing.T, c *websocket.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, _, err := c.Read(ctx); err == nil {
		t.Fatal("expected close")
	}
}
func TestHeartbeatTakeoverReplayAndShutdown(t *testing.T) {
	auth := &testAuth{}
	p := &testPresence{}
	s := New(auth, p, nil)
	h := httptest.NewServer(s)
	defer h.Close()
	defer s.Stop()
	first, a := connect(t, h.URL)
	defer first.CloseNow()
	send(t, first, message("presence.heartbeat", 1, a))
	if receive(t, first).Type != "presence.ack" {
		t.Fatal("missing heartbeat")
	}
	second, b := connect(t, h.URL)
	defer second.CloseNow()
	if b.Generation <= a.Generation || b.Fence == a.Fence {
		t.Fatal("not fenced")
	}
	assertClosed(t, first)
	send(t, second, message("presence.heartbeat", 1, b))
	receive(t, second)
	send(t, second, message("presence.heartbeat", 1, b))
	assertClosed(t, second)
	third, _ := connect(t, h.URL)
	defer third.CloseNow()
	s.Stop()
	assertClosed(t, third)
}
func TestCredentialRevocationClosesConnection(t *testing.T) {
	auth := &testAuth{}
	s := New(auth, &testPresence{}, nil)
	h := httptest.NewServer(s)
	defer h.Close()
	defer s.Stop()
	c, ack := connect(t, h.URL)
	defer c.CloseNow()
	auth.mu.Lock()
	auth.revoked = true
	auth.mu.Unlock()
	send(t, c, message("presence.heartbeat", 1, ack))
	assertClosed(t, c)
}
func TestRejectQueryTokenOriginAndAnonymous(t *testing.T) {
	s := New(&testAuth{}, &testPresence{}, nil)
	for _, tc := range []struct {
		url, origin, token string
		status             int
	}{{"http://local/?token=secret", "", "dev_test", 400}, {"http://local/", "http://evil", "dev_test", 400}, {"http://local/", "", "", 401}} {
		r := httptest.NewRequest("GET", tc.url, nil)
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		if tc.token != "" {
			r.Header.Set("Authorization", "Bearer "+tc.token)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("status %d", w.Code)
		}
	}
}
func TestDecodeLimits(t *testing.T) {
	good := message("hello", 0, Envelope{})
	data, _ := json.Marshal(good)
	if _, err := Decode(data); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{append(data, []byte(` {}`)...), []byte(`null`), []byte(`{"v":1,"unknown":true}`), make([]byte, MaxFrameBytes+1)} {
		if _, err := Decode(bad); err == nil {
			t.Fatal("accepted invalid envelope")
		}
	}
}

// Closing a socket must be distinguished from a read timing out: both return an
// error, but only the former proves Stop or revocation actually took effect.
func requireSocketClosed(t *testing.T, c *websocket.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, _, err := c.Read(ctx); err == nil {
		t.Fatal("connection delivered a message instead of closing")
	} else if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("connection remained open until the read deadline")
	}
}

func dialToken(t *testing.T, url, token string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(url, "http"), &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Bearer " + token}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestStopClosesUpgradedConnectionBeforeHello(t *testing.T) {
	s := New(&testAuth{}, &testPresence{}, nil)
	h := httptest.NewServer(s)
	defer h.Close()
	defer s.Stop()

	// The upgrade succeeds, but this connection is not yet a registered peer.
	c := dialToken(t, h.URL, "dev_test")
	defer c.CloseNow()
	stopped := make(chan struct{})
	go func() { s.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Stop blocked on a pending hello")
	}
	requireSocketClosed(t, c)
}

type independentlyRevocableAuth struct {
	mu      sync.Mutex
	revoked map[string]bool
}

func (a *independentlyRevocableAuth) Authenticate(_ context.Context, token string) (identity.Device, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if (token != "dev_old" && token != "dev_new") || a.revoked[token] {
		return identity.Device{}, errors.New("denied")
	}
	return identity.Device{ID: "device", TenantID: "tenant"}, nil
}

func TestRevokedDelayedHelloCannotReplaceCurrentConnection(t *testing.T) {
	auth := &independentlyRevocableAuth{revoked: make(map[string]bool)}
	leases := &testPresence{}
	s := New(auth, leases, nil)
	h := httptest.NewServer(s)
	defer h.Close()
	defer s.Stop()

	// The old credential is valid only for the upgrade, not for the later hello.
	old := dialToken(t, h.URL, "dev_old")
	defer old.CloseNow()
	auth.mu.Lock()
	auth.revoked["dev_old"] = true
	auth.mu.Unlock()

	current := dialToken(t, h.URL, "dev_new")
	defer current.CloseNow()
	send(t, current, message("hello", 0, Envelope{}))
	ack := receive(t, current)
	if ack.Type != "hello.ack" {
		t.Fatal("current credential did not establish its connection")
	}

	send(t, old, message("hello", 0, Envelope{}))
	requireSocketClosed(t, old)
	leases.mu.Lock()
	owner := leases.current
	leases.mu.Unlock()
	if owner.Generation != ack.Generation || owner.Token != ack.Fence {
		t.Fatal("revoked delayed hello changed Redis ownership")
	}
	heartbeat := message("presence.heartbeat", 1, ack)
	send(t, current, heartbeat)
	response := receive(t, current)
	if response.Type != "presence.ack" || response.RequestID != heartbeat.ID || response.Fence != ack.Fence {
		t.Fatal("revoked delayed hello displaced the current connection")
	}
}

type blockedRenewPresence struct {
	*testPresence
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (p *blockedRenewPresence) Renew(ctx context.Context, tenant, device string, lease presence.Lease) error {
	p.once.Do(func() { close(p.entered) })
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.release:
		return p.testPresence.Renew(ctx, tenant, device, lease)
	}
}

func TestStopDoesNotWaitForPresenceIOUnderGlobalLock(t *testing.T) {
	leases := &blockedRenewPresence{
		testPresence: &testPresence{},
		entered:      make(chan struct{}),
		release:      make(chan struct{}),
	}
	s := New(&testAuth{}, leases, nil)
	h := httptest.NewServer(s)
	defer h.Close()
	defer s.Stop()
	// Always release the fake dependency before server cleanup, including failure.
	defer close(leases.release)

	c := dialToken(t, h.URL, "dev_test")
	defer c.CloseNow()
	send(t, c, message("hello", 0, Envelope{}))
	select {
	case <-leases.entered:
	case <-time.After(time.Second):
		t.Fatal("server did not reach the controlled Redis barrier")
	}
	stopped := make(chan struct{})
	go func() { s.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Stop waited for Redis while holding the global server lock")
	}
	requireSocketClosed(t, c)
}
