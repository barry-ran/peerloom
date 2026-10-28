package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/barry-ran/peerloom/src/device-server/internal/adminauth"
	"github.com/barry-ran/peerloom/src/device-server/internal/config"
	"github.com/barry-ran/peerloom/src/device-server/internal/database"
	"github.com/barry-ran/peerloom/src/device-server/internal/management"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type options struct {
	command, tenant, username, userID, password string
	scope                                       management.Scope
	enabled                                     *bool
}

func parseOptions(args []string, input io.Reader) (options, error) {
	if len(args) == 0 || (args[0] != "create" && args[0] != "change") {
		return options{}, errors.New("usage: device-admin-user create|change --offline --tenant-id UUID [--password-stdin]; no default account")
	}
	flags := flag.NewFlagSet("device-admin-user", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	offline := flags.Bool("offline", false, "explicit local database-operator action")
	tenant := flags.String("tenant-id", "", "existing tenant UUID")
	username := flags.String("username", "", "new lowercase username")
	userID := flags.String("user-id", "", "existing administrator UUID")
	scope := flags.String("scope", "", "explicit read or admin role")
	passwordStdin := flags.Bool("password-stdin", false, "read secret passphrase from bounded stdin, never an argument")
	enable := flags.Bool("enable", false, "explicitly re-enable user; old sessions stay revoked")
	disable := flags.Bool("disable", false, "disable user and revoke all browser sessions")
	if err := flags.Parse(args[1:]); err != nil {
		return options{}, errors.New("invalid command arguments")
	}
	if !*offline || *tenant == "" || flags.NArg() != 0 {
		return options{}, errors.New("explicit --offline and --tenant-id required")
	}
	if args[0] == "create" && (*username == "" || !*passwordStdin || *scope == "" || *userID != "" || *disable || *enable) {
		return options{}, errors.New("create requires --username --scope --password-stdin")
	}
	if args[0] == "change" && (*userID == "" || *username != "") {
		return options{}, errors.New("change requires --user-id and cannot rename username")
	}
	if *enable && *disable {
		return options{}, errors.New("--enable and --disable are mutually exclusive")
	}
	if *scope != "" && *scope != "read" && *scope != "admin" {
		return options{}, errors.New("scope must be read or admin")
	}
	if args[0] == "change" && !*passwordStdin && *scope == "" && !*enable && !*disable {
		return options{}, errors.New("change requires a password, scope, enable or disable action")
	}
	password := ""
	if *passwordStdin {
		data, err := io.ReadAll(io.LimitReader(input, 1027))
		if err != nil || len(data) > 1026 {
			return options{}, errors.New("cannot read bounded password input")
		}
		password = strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
		if !utf8.ValidString(password) || utf8.RuneCountInString(password) < 15 || len(password) > 1024 || strings.TrimSpace(password) == "" || strings.ContainsRune(password, 0) {
			return options{}, errors.New("password must contain 15 or more characters and at most 1024 UTF-8 bytes")
		}
	}
	var enabled *bool
	if *enable || *disable {
		value := *enable
		enabled = &value
	}
	return options{command: args[0], tenant: *tenant, username: *username, userID: *userID, password: password, scope: management.Scope(*scope), enabled: enabled}, nil
}

func run(args []string) error {
	option, err := parseOptions(args, os.Stdin)
	if err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if option.command == "create" {
		id, err := adminauth.CreateUser(ctx, pool, option.tenant, option.username, option.password, option.scope)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"user_id": id, "status": "created"})
	}
	if err := adminauth.UpdateUser(ctx, pool, option.tenant, option.userID, adminauth.UserChange{Password: option.password, Scope: option.scope, Enabled: option.enabled}); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"user_id": option.userID, "status": "updated_sessions_revoked"})
}
