package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
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
	reference := flags.String("secret-ref", "", "immutable reference in RELAY_REGISTRY_FILE, never a path")
	enabled := flags.Bool("enabled", true, "enable or disable shared relay")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !*offline || flags.NArg() != 0 || *id == "" || *name == "" || *endpoint == "" || *reference == "" {
		return errors.New("shared relay requires --offline --node-id --name --endpoint --secret-ref")
	}
	issuer, _, err := relay.LoadFromEnvironment(os.Getenv)
	if err != nil {
		return errors.New("cannot load approved relay registry")
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
	input := relay.SharedNodeInput{ID: *id, Name: *name, Region: *region, Endpoint: *endpoint, SecretRef: *reference, Enabled: *enabled}
	if err = relay.SetSharedNode(ctx, pool, issuer, input); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"id": *id, "enabled": *enabled})
}
