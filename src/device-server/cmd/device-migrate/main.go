package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/config"
	"github.com/barry-ran/peerloom/src/device-server/internal/database"
	"github.com/barry-ran/peerloom/src/device-server/internal/migrate"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	dir := flag.String("dir", "infra/migrations", "reviewed SQL migration directory")
	flag.Parse()
	if flag.NArg() != 1 || (flag.Arg(0) != "up" && flag.Arg(0) != "down") {
		return fmt.Errorf("usage: device-migrate --dir DIR up|down (down removes one version)")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ms, err := migrate.Load(*dir)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err = migrate.Apply(ctx, pool, ms, flag.Arg(0)); err != nil {
		return err
	}
	fmt.Println("migration operation completed")
	return nil
}
