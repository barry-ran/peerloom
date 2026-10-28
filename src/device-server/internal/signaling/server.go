package signaling

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"hash/fnv"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/identity"
	"github.com/barry-ran/peerloom/src/device-server/internal/presence"
	"github.com/coder/websocket"
)

type Authenticator interface {
	Authenticate(context.Context, string) (identity.Device, error)
}
type Delivery struct {
	DeviceID string
	TenantID string
	Message  Envelope
}
type Dispatch func(context.Context, identity.Device, Envelope) ([]Delivery, error)
type peer struct {
	token  string
	device identity.Device
	lease  presence.Lease
	conn   *websocket.Conn
	out    chan Envelope
	cancel context.CancelFunc
}
type Server struct {
	installs    [64]sync.Mutex
	connections map[*websocket.Conn]context.CancelFunc
	handlers    sync.WaitGroup
	auth        Authenticator
	presence    presence.Store
	dispatch    Dispatch
	mu          sync.Mutex
	peers       map[string]*peer
	stopped     bool
	slots       chan struct{}
}

func New(auth Authenticator, store presence.Store, dispatch Dispatch) *Server {
	return &Server{auth: auth, presence: store, dispatch: dispatch, peers: make(map[string]*peer), connections: make(map[*websocket.Conn]context.CancelFunc), slots: make(chan struct{}, 256)}
}
func peerKey(d identity.Device) string { return d.TenantID + ":" + d.ID }
func uuid() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("system randomness unavailable")
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet || r.URL.RawQuery != "" || r.Header.Get("Origin") != "" {
		http.Error(w, "native signaling endpoint", http.StatusBadRequest)
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		http.Error(w, "capacity unavailable", 503)
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == r.Header.Get("Authorization") || !strings.HasPrefix(token, "dev_") {
		http.Error(w, "unauthorized", 401)
		return
	}
	authCtx, authCancel := context.WithTimeout(r.Context(), 3*time.Second)
	device, err := s.auth.Authenticate(authCtx, token)
	authCancel()
	if err != nil {
		http.Error(w, "unauthorized", 401)
		return
	}
	s.mu.Lock()
	stopped := s.stopped
	s.mu.Unlock()
	if stopped {
		http.Error(w, "stopping", 503)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer conn.CloseNow()
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.connections[conn] = cancel
	s.handlers.Add(1)
	defer s.handlers.Done()
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.connections, conn); s.mu.Unlock() }()
	conn.SetReadLimit(MaxFrameBytes)
	helloCtx, helloCancel := context.WithTimeout(ctx, 10*time.Second)
	typ, data, err := conn.Read(helloCtx)
	helloCancel()
	if err != nil || typ != websocket.MessageText {
		return
	}
	hello, err := Decode(data)
	if err != nil || hello.Type != "hello" || hello.Seq != 0 || hello.Generation != 0 || hello.Fence != "" || hello.SessionID != "" || !EmptyPayload(hello) {
		conn.Close(websocket.StatusPolicyViolation, "invalid hello")
		return
	}
	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte(peerKey(device)))
	install := &s.installs[hasher.Sum32()%uint32(len(s.installs))]
	install.Lock()
	if ctx.Err() != nil {
		install.Unlock()
		return
	}
	installed := false
	defer func() {
		if !installed {
			install.Unlock()
		}
	}()
	renewAuthCtx, renewAuthCancel := context.WithTimeout(ctx, 3*time.Second)
	fresh, authErr := s.auth.Authenticate(renewAuthCtx, token)
	renewAuthCancel()
	if authErr != nil || fresh.ID != device.ID || fresh.TenantID != device.TenantID {
		return
	}
	leaseCtx, leaseCancel := context.WithTimeout(ctx, 3*time.Second)
	lease, err := s.presence.Claim(leaseCtx, device.TenantID, device.ID)
	leaseCancel()
	if err != nil {
		conn.Close(websocket.StatusTryAgainLater, "presence unavailable")
		return
	}
	defer func() {
		releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer releaseCancel()
		_ = s.presence.Release(releaseCtx, device.TenantID, device.ID, lease)
	}()
	p := &peer{token: token, device: device, lease: lease, conn: conn, out: make(chan Envelope, 32), cancel: cancel}
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	previous := s.peers[peerKey(device)]
	s.peers[peerKey(device)] = p
	s.mu.Unlock()
	installed = true
	install.Unlock()
	if previous != nil {
		previous.cancel()
		previous.conn.CloseNow()
	}
	defer func() {
		s.mu.Lock()
		if s.peers[peerKey(device)] == p {
			delete(s.peers, peerKey(device))
		}
		s.mu.Unlock()
	}()
	writerDone := make(chan struct{})
	go func() { defer close(writerDone); s.write(ctx, p) }()
	defer func() { cancel(); conn.CloseNow(); <-writerDone }()
	payload, _ := json.Marshal(map[string]int{"heartbeat_interval_seconds": 15, "presence_ttl_seconds": 45})
	p.out <- Envelope{Type: "hello.ack", RequestID: hello.ID, Payload: payload}
	var seq int64
	recent := map[string]struct{}{hello.ID: {}}
	var ids [256]string
	ids[0] = hello.ID
	nextID := 1
	window := time.Now()
	count := 0
	for {
		readCtx, readCancel := context.WithTimeout(ctx, presence.LeaseTTL)
		typ, data, err = conn.Read(readCtx)
		readCancel()
		if err != nil {
			return
		}
		if typ != websocket.MessageText {
			conn.Close(websocket.StatusUnsupportedData, "text required")
			return
		}
		now := time.Now()
		if now.Sub(window) >= time.Second {
			window = now
			count = 0
		}
		count++
		if count > 60 {
			conn.Close(websocket.StatusPolicyViolation, "rate exceeded")
			return
		}
		e, err := Decode(data)
		if err != nil || e.Seq != seq+1 || e.Generation != lease.Generation || e.Fence != lease.Token {
			conn.Close(websocket.StatusPolicyViolation, "invalid ownership or sequence")
			return
		}
		if _, duplicate := recent[e.ID]; duplicate {
			conn.Close(websocket.StatusPolicyViolation, "duplicate message")
			return
		}
		delete(recent, ids[nextID])
		ids[nextID] = e.ID
		recent[e.ID] = struct{}{}
		nextID = (nextID + 1) % len(ids)
		seq = e.Seq
		checkCtx, checkCancel := context.WithTimeout(ctx, 3*time.Second)
		current, authErr := s.auth.Authenticate(checkCtx, token)
		if authErr == nil && current.ID == device.ID && current.TenantID == device.TenantID {
			authErr = s.presence.Renew(checkCtx, device.TenantID, device.ID, lease)
		}
		checkCancel()
		if authErr != nil || current.ID != device.ID || current.TenantID != device.TenantID {
			conn.Close(websocket.StatusPolicyViolation, "authorization or ownership expired")
			return
		}
		if e.Type == "presence.heartbeat" && EmptyPayload(e) && e.SessionID == "" {
			if !s.deliver(device.TenantID, device.ID, Envelope{Type: "presence.ack", RequestID: e.ID, Payload: json.RawMessage(`{}`)}) {
				return
			}
			continue
		}
		if s.dispatch == nil {
			conn.Close(websocket.StatusPolicyViolation, "unsupported message")
			return
		}
		actionCtx, actionCancel := context.WithTimeout(ctx, 5*time.Second)
		deliveries, actionErr := s.dispatch(actionCtx, current, e)
		actionCancel()

		for _, delivery := range deliveries {
			if delivery.TenantID != device.TenantID {
				continue
			}
			s.deliver(delivery.TenantID, delivery.DeviceID, delivery.Message)
		}
		if actionErr != nil {
			failurePayload, _ := json.Marshal(map[string]string{"code": failureCode(actionErr)})
			s.deliver(device.TenantID, device.ID, Envelope{Type: "error", RequestID: e.ID, Payload: failurePayload})
			continue
		}
	}
}
func (s *Server) write(ctx context.Context, p *peer) {
	var seq int64
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-p.out:
			checkCtx, checkCancel := context.WithTimeout(ctx, 3*time.Second)
			_, authErr := s.auth.Authenticate(checkCtx, p.token)
			if authErr == nil {
				authErr = s.presence.Renew(checkCtx, p.device.TenantID, p.device.ID, p.lease)
			}
			checkCancel()
			if authErr != nil {
				p.cancel()
				return
			}
			e.Version = 1
			e.ID = uuid()
			e.Seq = seq
			seq++
			e.SentAt = time.Now().UTC().Format(time.RFC3339Nano)
			e.Generation = p.lease.Generation
			e.Fence = p.lease.Token
			data, err := json.Marshal(e)
			if err != nil || len(data) > MaxFrameBytes {
				p.cancel()
				return
			}
			writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err = p.conn.Write(writeCtx, websocket.MessageText, data)
			cancel()
			if err != nil {
				p.cancel()
				return
			}
		}
	}
}
func (s *Server) deliver(tenant, device string, e Envelope) bool {
	s.mu.Lock()
	p := s.peers[tenant+":"+device]
	s.mu.Unlock()
	if p == nil {
		return false
	}
	select {
	case p.out <- e:
		return true
	default:
		p.cancel()
		p.conn.CloseNow()
		return false
	}
}

// Stop also closes upgraded connections, which http.Server.Shutdown does not own.
func (s *Server) Stop() {
	s.mu.Lock()
	s.stopped = true
	connections := make([]*websocket.Conn, 0, len(s.connections))
	cancels := make([]context.CancelFunc, 0, len(s.connections))
	for conn, cancel := range s.connections {
		cancels = append(cancels, cancel)
		connections = append(connections, conn)
	}
	peers := make([]*peer, 0, len(s.peers))
	for _, p := range s.peers {
		peers = append(peers, p)
	}
	s.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	for _, conn := range connections {
		conn.CloseNow()
	}
	for _, p := range peers {
		p.cancel()
		p.conn.CloseNow()
	}
	s.handlers.Wait()
}
