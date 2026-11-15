package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/config"
	"github.com/barry-ran/peerloom/src/device-server/internal/database"
	"github.com/barry-ran/peerloom/src/device-server/internal/management"
)

// exclusiveOutput never replaces an existing credential file. The containing
// directory must be private; Unix mode bits do not replace Windows ACLs.
func exclusiveOutput(path string) (*os.File, error) {
	if path == "" {
		return nil, errors.New("secret output requires --output in a private directory")
	}
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
}
func writeSecret(f *os.File, value any) error {
	if err := json.NewEncoder(f).Encode(value); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return syncOutputDirectory(f.Name())
}
func runSetup(args []string) error {
	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	offline := flags.Bool("offline", false, "authorize first-install database administration")
	name := flags.String("tenant-name", "", "tenant name")
	app := flags.String("application-name", "", "application name")
	output := flags.String("output", "", "new secret JSON file in a private directory")
	ttl := flags.Duration("ttl", 30*24*time.Hour, "finite credential lifetime, 1m to 720h")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !*offline || *name == "" || *app == "" || *output == "" || flags.NArg() != 0 {
		return errors.New("setup requires --offline --tenant-name --application-name --output")
	}
	if *ttl < time.Minute || *ttl > 30*24*time.Hour {
		return errors.New("credential lifetime must be 1m to 720h")
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
	f, err := exclusiveOutput(*output)
	if err != nil {
		return err
	}
	defer f.Close()
	r, err := management.SetupEmpty(ctx, pool, *name, *app, *ttl, func(r management.SetupResult) error { return writeSecret(f, r) })
	if err != nil {
		var uncertain *management.CommitUncertainError
		if errors.As(err, &uncertain) {
			return fmt.Errorf("setup commit uncertain; output retained; verify database and output before retry: %w", err)
		}
		_ = f.Close()
		if removeErr := os.Remove(*output); removeErr != nil {
			return fmt.Errorf("setup rolled back but output cleanup failed: %w", removeErr)
		}
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"tenant_id": r.TenantID, "application_id": r.ApplicationID, "credential_id": r.CredentialID, "expires_at": r.ExpiresAt, "output": *output})
}

func readSetup(path string) (management.SetupResult, error) {
	f, err := openSetupInput(path)
	if err != nil {
		return management.SetupResult{}, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 16*1024+1))
	if err != nil {
		return management.SetupResult{}, err
	}
	if len(b) > 16*1024 {
		return management.SetupResult{}, errors.New("setup material too large")
	}
	var r management.SetupResult
	if err = json.Unmarshal(b, &r); err != nil {
		return management.SetupResult{}, errors.New("invalid setup JSON")
	}
	return r, nil
}
func runSetupVerify(args []string) error {
	flags := flag.NewFlagSet("setup-verify", flag.ContinueOnError)
	offline := flags.Bool("offline", false, "authorize local database inspection")
	input := flags.String("input", "", "existing setup JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if !*offline || *input == "" || flags.NArg() != 0 {
		return errors.New("setup-verify requires --offline --input")
	}
	material, err := readSetup(*input)
	if err != nil {
		return err
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
	status, err := management.VerifySetup(ctx, pool, material)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		management.KeyStatus
		ApplicationID string `json:"application_id"`
	}{status, material.ApplicationID})
}
