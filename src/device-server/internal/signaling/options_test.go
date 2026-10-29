package signaling

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOptionalCapacityPolicies(t *testing.T) {
	for _, value := range []string{"", "0", "501", "1000001"} {
		o, err := LoadOptions(func(string) string { return value })
		if err != nil {
			t.Fatal(err)
		}
		if value == "" && (o.MaxConnections != 0 || o.FramesPerSecond != 0) {
			t.Fatal("default must not impose policy caps")
		}
	}
	for _, value := range []string{"-1", "x", "999999999999999999999999"} {
		if _, err := LoadOptions(func(string) string { return value }); err == nil {
			t.Fatal("invalid capacity accepted")
		}
	}
	s := New(nil, nil, nil)
	s.admitted = 501
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 401 {
		t.Fatalf("unlimited admission must still enforce auth: %d", w.Code)
	}
	limited, err := NewWithOptions(nil, nil, nil, Options{MaxConnections: 1})
	if err != nil {
		t.Fatal(err)
	}
	limited.admitted = 1
	w = httptest.NewRecorder()
	limited.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 503 {
		t.Fatal("explicit connection cap ignored")
	}
}
func TestBoundedDeliveryWaitsForConsumerAndCancels(t *testing.T) {
	s := New(nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &peer{out: make(chan Envelope, 32), done: ctx.Done(), cancel: cancel}
	s.peers["t:d"] = p
	for i := 0; i < cap(p.out); i++ {
		p.out <- Envelope{}
	}
	done := make(chan bool, 1)
	go func() { done <- s.deliver("t", "d", Envelope{}) }()
	select {
	case <-done:
		t.Fatal("full bounded queue prematurely terminated delivery")
	case <-time.After(20 * time.Millisecond):
	}
	<-p.out
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("consumer progress rejected")
		}
	case <-time.After(time.Second):
		t.Fatal("delivery stuck")
	}
	cancel()
	if s.deliver("t", "d", Envelope{}) {
		t.Fatal("cancelled full queue accepted")
	}
}
