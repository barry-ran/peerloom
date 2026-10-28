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
	name := flag.String("name", "本地开发", "development tenant and application name")
	flag.Parse()
	if !*development || flag.NArg() != 0 {
		return fmt.Errorf("usage: device-bootstrap --development [--name NAME]; stdout contains a one-time secret")
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
	result, err := identity.BootstrapDevelopment(ctx, pool, *name)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
