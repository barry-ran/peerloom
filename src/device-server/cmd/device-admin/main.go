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
		return errors.New("usage: device-admin setup|bootstrap|issue-key|revoke-key|key-status --offline [options]; key output is secret")
	}
	command := args[0]
	if command == "setup-verify" {
		return runSetupVerify(args[1:])
	}
	if command == "setup" {
		return runSetup(args[1:])
	}
	if command == "relay-set-shared" {
		return runSharedRelay(args[1:])
	}
	if command != "bootstrap" && command != "issue-key" && command != "revoke-key" && command != "key-status" {
		return errors.New("unsupported offline administration command")
	}
	flags := flag.NewFlagSet("device-admin", flag.ContinueOnError)
	offline := flags.Bool("offline", false, "explicitly authorize this local database-operator action")
	tenant := flags.String("tenant-id", "", "existing tenant UUID")
	name := flags.String("tenant-name", "", "new tenant name for bootstrap")
	output := flags.String("output", "", "optional new secret JSON file instead of stdout")
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
	if command != "revoke-key" && command != "key-status" && *scope == "" {
		return errors.New("key issuance requires explicit --scope read|admin")
	}
	if (command == "revoke-key" || command == "key-status") && *credentialID == "" {
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
	var secretFile *os.File
	if *output != "" {
		if command != "bootstrap" && command != "issue-key" {
			return errors.New("--output only applies to key issuance")
		}
		secretFile, err = exclusiveOutput(*output)
		if err != nil {
			return err
		}
		defer secretFile.Close()
		// Check directory durability support before any issuance, including
		// the legacy bootstrap path which commits before emitting its result.
		if err := syncOutputDirectory(secretFile.Name()); err != nil {
			_ = secretFile.Close()
			_ = os.Remove(*output)
			return err
		}
	}
	emit := func(result management.KeyResult) error {
		if secretFile == nil {
			return json.NewEncoder(os.Stdout).Encode(result)
		}
		if err := writeSecret(secretFile, result); err != nil {
			return fmt.Errorf("key issued but output write failed; inspect and revoke credential %s: %w", result.CredentialID, err)
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"tenant_id": result.TenantID, "credential_id": result.CredentialID, "expires_at": result.ExpiresAt, "output": *output})
	}
	switch command {
	case "key-status":
		result, err := management.InspectKey(ctx, pool, *tenant, *credentialID)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	case "bootstrap":
		result, err := management.BootstrapKey(ctx, pool, *name, management.Scope(*scope), *ttl, *label)
		if err != nil {
			return err
		}
		return emit(result)
	case "issue-key":
		var persist func(management.KeyResult) error
		if secretFile != nil {
			persist = func(r management.KeyResult) error { return writeSecret(secretFile, r) }
		}
		result, err := management.IssueKeyPersisted(ctx, pool, *tenant, management.Scope(*scope), *ttl, *label, persist)
		if err != nil {
			return err
		}
		if secretFile != nil {
			return json.NewEncoder(os.Stdout).Encode(map[string]any{"tenant_id": result.TenantID, "credential_id": result.CredentialID, "expires_at": result.ExpiresAt, "output": *output})
		}
		return emit(result)
	default:
		if err := management.RevokeKey(ctx, pool, *tenant, *credentialID); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"status": "revoked", "credential_id": *credentialID})
	}
}
