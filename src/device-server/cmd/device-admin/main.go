package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/config"
	"github.com/barry-ran/peerloom/src/device-server/internal/database"
	"github.com/barry-ran/peerloom/src/device-server/internal/management"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: device-admin bootstrap|issue-key|revoke-key --offline [options]; key output is secret")
	}
	command := args[0]
	if command != "bootstrap" && command != "issue-key" && command != "revoke-key" {
		return errors.New("unsupported offline administration command")
	}
	flags := flag.NewFlagSet("device-admin", flag.ContinueOnError)
	offline := flags.Bool("offline", false, "explicitly authorize this local database-operator action")
	tenant := flags.String("tenant-id", "", "existing tenant UUID")
	name := flags.String("tenant-name", "", "new tenant name for bootstrap")
	scope := flags.String("scope", "", "required read or admin scope when issuing")
	ttl := flags.Duration("ttl", 24*time.Hour, "credential lifetime, 1m to 720h")
	label := flags.String("label", "offline-issued", "nonsecret operator label")
	credentialID := flags.String("credential-id", "", "credential UUID for revocation")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if !*offline || flags.NArg() != 0 {
		return errors.New("offline operator action requires explicit --offline")
	}
	if command == "bootstrap" && (*name == "" || *tenant != "") {
		return errors.New("bootstrap requires --tenant-name and does not adopt an existing tenant")
	}
	if command != "bootstrap" && *tenant == "" {
		return errors.New("existing-tenant command requires --tenant-id")
	}
	if command != "revoke-key" && *scope == "" {
		return errors.New("key issuance requires explicit --scope read|admin")
	}
	if command == "revoke-key" && *credentialID == "" {
		return errors.New("revocation requires --credential-id")
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
	switch command {
	case "bootstrap":
		result, err := management.BootstrapKey(ctx, pool, *name, management.Scope(*scope), *ttl, *label)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	case "issue-key":
		result, err := management.IssueKey(ctx, pool, *tenant, management.Scope(*scope), *ttl, *label)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	default:
		if err := management.RevokeKey(ctx, pool, *tenant, *credentialID); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"status": "revoked", "credential_id": *credentialID})
	}
}
