// MIT — Copyright (c) 2026 Peerloom contributors.
// CI-only client: compiled outside the delivered package and never copied into its image.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	address := flag.String("address", "", "owned egress fixture IP")
	ca := flag.String("ca", "", "synthetic CA file")
	reject := flag.Bool("reject", false, "require unknown-authority rejection")
	flag.Parse()
	if net.ParseIP(*address) == nil || flag.NArg() != 0 {
		os.Exit(2)
	}
	data, err := os.ReadFile(*ca)
	if err != nil {
		os.Exit(2)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		os.Exit(2)
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", net.JoinHostPort(*address, "8443"))
		}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect rejected") }}
	response, err := client.Get("https://localhost:8443/healthz")
	if *reject {
		if response != nil {
			response.Body.Close()
		}
		var unknown x509.UnknownAuthorityError
		if err != nil && errors.As(err, &unknown) {
			return
		}
		os.Exit(1)
	}
	if err != nil {
		os.Exit(1)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 32))
	if err != nil || response.StatusCode != 200 || string(body) != "egress-ok" {
		os.Exit(1)
	}
}
