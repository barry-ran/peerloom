package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/config"
	"github.com/barry-ran/peerloom/src/device-server/internal/database"
	"github.com/barry-ran/peerloom/src/device-server/internal/httpapi"
	"github.com/barry-ran/peerloom/src/device-server/internal/httpserver"
	"github.com/barry-ran/peerloom/src/device-server/internal/identity"
	"github.com/barry-ran/peerloom/src/device-server/internal/migrate"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	pool, err := database.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	key, err := identity.ReadReplayKey(os.Getenv("REPLAY_KEY_FILE"))
	if err != nil {
		return err
	}
	settings, err := identity.LoadSettings(os.Getenv)
	if err != nil {
		return err
	}
	store, err := identity.NewWithSettings(pool, key, settings)
	if err != nil {
		return errors.New("cannot initialize identity service")
	}
	cleanupCtx, cleanupCancel := context.WithCancel(ctx)
	cleanupDone := make(chan struct{})
	go func() {
		defer close(cleanupDone)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-cleanupCtx.Done():
				return
			case <-ticker.C:
				queryCtx, cancel := context.WithTimeout(cleanupCtx, 3*time.Second)
				if err := store.PurgeExpired(queryCtx); err != nil && cleanupCtx.Err() == nil {
					logger.Warn("expired identity replay cleanup unavailable")
				}
				cancel()
			}
		}
	}()
	defer func() { cleanupCancel(); <-cleanupDone }()
	handler := httpserver.New(database.Ready(pool, migrate.CurrentVersion), httpapi.New(store))
	server := &http.Server{Addr: cfg.ListenAddress, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	logger.Info("server starting", "address", cfg.ListenAddress)
	select {
	case err = <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			return errors.New("HTTP listener failed")
		}
		return nil
	case <-ctx.Done():
		handler.Stop()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if err = server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			return errors.New("HTTP shutdown deadline exceeded")
		}
		<-done
		logger.Info("server stopped gracefully")
		return nil
	}
}
