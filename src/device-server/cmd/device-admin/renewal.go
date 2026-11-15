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
	"github.com/barry-ran/peerloom/src/device-server/internal/identity"
	"github.com/barry-ran/peerloom/src/device-server/internal/management"
)

func runRenewalCommand(command string, args []string) error {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	offline := fs.Bool("offline", false, "authorize trusted local database administration")
	input := fs.String("input", "", "existing credential JSON")
	output := fs.String("output", "", "new private credential JSON file, never overwritten")
	op := fs.String("operation-id", "", "persisted high-entropy renewal operation")
	tenant := fs.String("tenant-id", "", "subject tenant")
	subject := fs.String("subject-id", "", "subject to revoke, invalidates all keys")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*offline || fs.NArg() != 0 {
		return errors.New("requires --offline")
	}
	if command != "renew-key" {
		if *tenant == "" || *subject == "" || *input != "" || *output != "" || *op != "" {
			return errors.New("subject administration requires --tenant-id --subject-id only")
		}
	} else if *input == "" || *output == "" || *op == "" || *tenant != "" || *subject != "" {
		return errors.New("renew-key requires --input --output --operation-id")
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
	if command != "renew-key" {
		if command == "revoke-subject" {
			return management.RevokeSubject(ctx, pool, *tenant, *subject)
		}
		return management.SetSubjectRenewal(ctx, pool, *tenant, *subject, command == "enable-renewal")
	}
	material, err := readSetup(*input)
	if err != nil {
		return err
	}
	key, err := identity.ReadReplayKey(os.Getenv("REPLAY_KEY_FILE"))
	if err != nil {
		return err
	}
	service, err := management.New(pool, key, management.DefaultSettings())
	if err != nil {
		return err
	}
	p, err := service.Authenticate(ctx, material.ServiceCredential)
	if err != nil {
		return err
	}
	if p.TenantID() != material.TenantID || p.CredentialID() != material.CredentialID {
		return errors.New("credential JSON does not match authenticated identity")
	}
	f, err := exclusiveOutput(*output)
	if err != nil {
		return err
	}
	defer f.Close()
	r, err := service.RenewServiceKeyPersisted(ctx, p, *op, func(r management.ServiceKeyRenewal) error {
		value := struct {
			management.ServiceKeyRenewal
			ApplicationID   string `json:"application_id,omitempty"`
			ApplicationName string `json:"application_name,omitempty"`
			TenantName      string `json:"tenant_name,omitempty"`
		}{r, material.ApplicationID, material.ApplicationName, material.TenantName}
		return writeSecret(f, value)
	})
	if err != nil {
		var uncertain *management.CommitUncertainError
		if errors.As(err, &uncertain) {
			return fmt.Errorf("renewal commit uncertain; retain output and retry the same operation only after verification: %w", err)
		}
		_ = f.Close()
		if removeErr := os.Remove(*output); removeErr != nil {
			return fmt.Errorf("renewal failed; output cleanup failed: %w", removeErr)
		}
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(r.ServiceKeySelf)
}
