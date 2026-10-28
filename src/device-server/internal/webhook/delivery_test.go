package webhook

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPSDeliverySignatureTrustAndNoRedirect(t *testing.T) {
	binding := goodBinding()
	id := "00000000-0000-4000-8000-000000000001"
	body := []byte(`{"event":"application.create"}`)
	var reached atomic.Int32
	var response atomic.Int32
	response.Store(204)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		data, err := io.ReadAll(io.LimitReader(r.Body, 65537))
		if err != nil || string(data) != string(body) || r.Method != http.MethodPost {
			t.Error("request shape")
		}
		stamp := r.Header.Get("Peerloom-Timestamp")
		if stamp == "" || r.Header.Get("Peerloom-Delivery-ID") != id || r.Header.Get("Peerloom-Signature") != signature(binding.Secret, id, stamp, data) {
			t.Error("signature binding")
		}
		if response.Load() == 302 {
			w.Header().Set("Location", "/must-not-follow")
		}
		w.WriteHeader(int(response.Load()))
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	binding.URL = server.URL
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client := func(pool *x509.CertPool) *http.Client {
		transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	trusted := client(roots)
	if status, err := sendRequest(context.Background(), trusted, binding, id, body); err != nil || status != 204 {
		t.Fatalf("trusted TLS: %d %v", status, err)
	}
	before := reached.Load()
	if _, err := sendRequest(context.Background(), client(x509.NewCertPool()), binding, id, body); err == nil {
		t.Fatal("wrong CA accepted")
	}
	if reached.Load() != before {
		t.Fatal("untrusted TLS reached handler")
	}
	response.Store(302)
	if status, err := sendRequest(context.Background(), trusted, binding, id, body); err == nil || status != 302 {
		t.Fatalf("redirect accepted: %d %v", status, err)
	}
	if reached.Load() != before+1 {
		t.Fatal("redirect followed")
	}
}
