package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type Sender struct{ registry *Registry }

func NewSender(registry *Registry) *Sender { return &Sender{registry: registry} }
func signature(secret, id, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(timestamp + "." + id + "."))
	_, _ = mac.Write(body)
	return "v1=" + hex.EncodeToString(mac.Sum(nil))
}

// Send never follows redirects, uses environment proxies, or resolves a caller
// supplied hostname. Registry addresses are an explicit operator egress allowlist.
// HTTP error bodies are discarded, not logged or exposed to tenants.
func (s *Sender) Send(ctx context.Context, tenant, ref, target, id string, body []byte) (int, error) {
	b, ok := s.registry.lookup(tenant, ref, target)
	if !ok || !uuid.MatchString(id) || len(body) == 0 || len(body) > 65536 {
		return 0, errors.New("webhook delivery not approved")
	}
	u, _ := url.Parse(b.URL)
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true, ForceAttemptHTTP2: false, MaxResponseHeaderBytes: 8192, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 3 * time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != net.JoinHostPort(u.Hostname(), "443") {
			return nil, errors.New("unapproved webhook destination")
		}
		dialer := net.Dialer{Timeout: 2 * time.Second}
		for _, ip := range b.Addresses {
			conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
			if err == nil {
				return conn, nil
			}
			if ctx.Err() != nil {
				break
			}
		}
		return nil, errors.New("webhook connection unavailable")
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return sendRequest(ctx, client, b, id, body)
}

func sendRequest(ctx context.Context, client *http.Client, b Binding, id string, body []byte) (int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, b.URL, bytes.NewReader(body))
	if err != nil {
		return 0, errors.New("webhook request unavailable")
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "Peerloom-Webhook/1")
	request.Header.Set("Peerloom-Delivery-ID", id)
	request.Header.Set("Peerloom-Timestamp", timestamp)
	request.Header.Set("Peerloom-Signature", signature(b.Secret, id, timestamp, body))
	response, err := client.Do(request)
	if err != nil {
		return 0, errors.New("webhook transport unavailable")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return response.StatusCode, errors.New("webhook receiver rejected delivery")
	}
	return response.StatusCode, nil
}

func (Sender) String() string   { return "[REDACTED webhook sender]" }
func (Sender) GoString() string { return "[REDACTED webhook sender]" }
