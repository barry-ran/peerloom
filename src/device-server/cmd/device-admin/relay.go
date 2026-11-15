package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/config"
	"github.com/barry-ran/peerloom/src/device-server/internal/database"
	"github.com/barry-ran/peerloom/src/device-server/internal/relay"
)

func runSharedRelay(args []string) error {
	flags := flag.NewFlagSet("device-admin relay-set-shared", flag.ContinueOnError)
	offline := flags.Bool("offline", false, "explicit database operator authority for shared relay")
	id := flags.String("node-id", "", "stable shared node UUID")
	name := flags.String("name", "", "node display name")
	region := flags.String("region", "", "nonsecret region label")
	endpoint := flags.String("endpoint", "", "single operator-approved TURN URL")
	secretFile := flags.String("secret-file", "", "private file containing exact printable coturn shared secret; omit to retain current version")
	enabled := flags.Bool("enabled", true, "enable or disable shared relay")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !*offline || flags.NArg() != 0 || *id == "" || *name == "" || *endpoint == "" {
		return errors.New("shared relay requires --offline --node-id --name --endpoint [--secret-file FILE]")
	}
	issuer, _, err := relay.LoadFromEnvironment(os.Getenv)
	if err != nil {
		return errors.New("cannot load relay encryption configuration")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	var secret *string
	if *secretFile != "" {
		f, openErr := os.Open(*secretFile)
		if openErr != nil {
			return errors.New("cannot read shared secret file")
		}
		info, statErr := f.Stat()
		if statErr != nil || !info.Mode().IsRegular() {
			f.Close()
			return errors.New("invalid shared secret file")
		}
		body, readErr := io.ReadAll(io.LimitReader(f, 257))
		f.Close()
		if readErr != nil || len(body) > 256 {
			return errors.New("invalid shared secret file")
		}
		v := string(body)
		secret = &v
		defer clear(body)
	}
	input := relay.SharedNodeInput{ID: *id, Name: *name, Region: *region, Endpoint: *endpoint, Secret: secret, Enabled: *enabled}
	if err = relay.SetSharedNode(ctx, pool, issuer, input); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"id": *id, "enabled": *enabled})
}
