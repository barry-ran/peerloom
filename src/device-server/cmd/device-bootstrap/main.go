package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/config"
	"github.com/barry-ran/peerloom/src/device-server/internal/database"
	"github.com/barry-ran/peerloom/src/device-server/internal/identity"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	development := flag.Bool("development", false, "explicitly create one development tenant/application/one-time grant")
	pair := flag.Bool("pair", false, "create two registered development devices and a directional approval-required grant; stdout contains credentials")
	name := flag.String("name", "本地开发", "development tenant and application name")
	flag.Parse()
	if !*development || flag.NArg() != 0 {
		return fmt.Errorf("usage: device-bootstrap --development [--pair] [--name NAME]; stdout contains secrets")
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
	if *pair {
		key, keyErr := identity.ReadReplayKey(os.Getenv("REPLAY_KEY_FILE"))
		if keyErr != nil {
			return keyErr
		}
		settings, settingsErr := identity.LoadSettings(os.Getenv)
		if settingsErr != nil {
			return settingsErr
		}
		result, pairErr := createPair(ctx, pool, key, settings, *name)
		if pairErr != nil {
			return pairErr
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	result, err := identity.BootstrapDevelopment(ctx, pool, *name)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
