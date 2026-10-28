package main

import (
	"context"
	"errors"
	"github.com/barry-ran/peerloom/src/device-server/internal/presence"
	"github.com/barry-ran/peerloom/src/device-server/internal/signaling"
	"github.com/redis/go-redis/v9"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/barry-ran/peerloom/src/device-server/internal/adminauth"
	"github.com/barry-ran/peerloom/src/device-server/internal/adminweb"
	"github.com/barry-ran/peerloom/src/device-server/internal/authorization"
	"github.com/barry-ran/peerloom/src/device-server/internal/config"
	"github.com/barry-ran/peerloom/src/device-server/internal/database"
	"github.com/barry-ran/peerloom/src/device-server/internal/httpapi"
	"github.com/barry-ran/peerloom/src/device-server/internal/httpserver"
	"github.com/barry-ran/peerloom/src/device-server/internal/identity"
	"github.com/barry-ran/peerloom/src/device-server/internal/management"
	"github.com/barry-ran/peerloom/src/device-server/internal/migrate"
	"github.com/barry-ran/peerloom/src/device-server/internal/relay"
	"github.com/barry-ran/peerloom/src/device-server/internal/webhook"
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
	redisAddress := os.Getenv("REDIS_ADDRESS")
	if redisAddress == "" {
		redisAddress = "redis:6379"
	}
	redisPassword, err := os.ReadFile(os.Getenv("REDIS_PASSWORD_FILE"))
	if err != nil || len(strings.TrimSpace(string(redisPassword))) < 16 {
		return errors.New("valid REDIS_PASSWORD_FILE required")
	}
	cache := redis.NewClient(&redis.Options{Addr: redisAddress, Password: strings.TrimSpace(string(redisPassword)), DialTimeout: 3 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, PoolSize: 16, MaxActiveConns: 32, MaxRetries: 1, ContextTimeoutEnabled: true})
	defer cache.Close()
	online := presence.NewRedis(cache)
	sessions, err := authorization.New(pool, online, authorization.DefaultOptions())
	if err != nil {
		return errors.New("cannot initialize authorization service")
	}
	signalingServer := signaling.New(store, online, signaling.AuthorizationDispatch(sessions))
	defer signalingServer.Stop()
	sweepCtx, sweepCancel := context.WithCancel(ctx)
	sweepDone := make(chan struct{})
	go func() {
		defer close(sweepDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		sweepFailed := false
		for {
			select {
			case <-sweepCtx.Done():
				return
			case <-ticker.C:
				operationCtx, cancel := context.WithTimeout(sweepCtx, 3*time.Second)
				closed, err := sessions.SweepExpired(operationCtx)
				cancel()
				if err != nil && sweepCtx.Err() == nil && !sweepFailed {
					logger.Warn("session expiry sweep unavailable")
				}
				sweepFailed = err != nil
				for _, session := range closed {
					signalingServer.NotifySession(session)
				}
			}
		}
	}()
	defer func() { sweepCancel(); <-sweepDone }()
	relayIssuer, relayLimits, err := relay.LoadFromEnvironment(os.Getenv)
	if err != nil {
		return errors.New("cannot initialize relay registry")
	}
	relayService, err := relay.NewService(pool, relayIssuer, sessions, relayLimits)
	if err != nil {
		return errors.New("cannot initialize relay service")
	}
	administration, err := management.NewWithRelay(pool, key, management.DefaultSettings(), online, relayIssuer)
	if err != nil {
		return errors.New("cannot initialize management service")
	}
	webhookRegistry, err := webhook.Load(os.Getenv("WEBHOOK_REGISTRY_FILE"))
	if err != nil {
		return errors.New("cannot initialize webhook registry")
	}
	administration, err = administration.WithWebhooks(webhookRegistry)
	if err != nil {
		return errors.New("cannot bind webhook registry")
	}
	webhookWorker, err := webhook.NewWorker(pool, webhook.NewSender(webhookRegistry))
	if err != nil {
		return errors.New("cannot initialize webhook worker")
	}
	webhookCtx, webhookCancel := context.WithCancel(ctx)
	webhookDone := make(chan struct{})
	go func() { defer close(webhookDone); webhookWorker.Run(webhookCtx) }()
	defer func() { webhookCancel(); <-webhookDone }()
	// Browser administration is explicitly enabled only for a canonical operator
	// origin. It never creates an account and never accepts service credentials.
	var browserAuth *adminauth.Service
	var browserHandler *adminauth.Handler
	if origin := os.Getenv("ADMIN_ORIGIN"); origin != "" {
		browserAuth, err = adminauth.New(pool)
		if err != nil {
			return errors.New("cannot initialize browser authentication")
		}
		administration, err = administration.WithBrowserAuthority(browserAuth)
		if err != nil {
			return errors.New("cannot bind browser authority")
		}
		development := os.Getenv("ADMIN_DEVELOPMENT_LOOPBACK")
		if development != "" && development != "true" {
			return errors.New("ADMIN_DEVELOPMENT_LOOPBACK must be empty or true")
		}
		browserHandler, err = adminauth.NewHandler(browserAuth, management.NewHandler(administration, signalingServer.NotifySession), adminauth.HTTPConfig{Origin: origin, DevelopmentLoopback: development == "true"})
		if err != nil {
			return err
		}
	} else if os.Getenv("ADMIN_DEVELOPMENT_LOOPBACK") != "" {
		return errors.New("ADMIN_ORIGIN required with development mode")
	}
	managementCtx, managementCancel := context.WithCancel(ctx)
	managementDone := make(chan struct{})
	go func() {
		defer close(managementDone)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-managementCtx.Done():
				return
			case <-ticker.C:
				operationCtx, cancel := context.WithTimeout(managementCtx, 3*time.Second)
				err := administration.PurgeExpired(operationCtx)
				if err == nil {
					err = relayService.PurgeExpired(operationCtx)
				}
				if err == nil {
					err = webhookWorker.Purge(operationCtx)
				}
				if err == nil && browserAuth != nil {
					err = browserAuth.PurgeExpired(operationCtx)
				}
				cancel()
				if err != nil && managementCtx.Err() == nil {
					logger.Warn("expired management replay cleanup unavailable")
				}
			}
		}
	}()
	defer func() { managementCancel(); <-managementDone }()
	api := http.NewServeMux()
	managementHandler := management.NewHandler(administration, signalingServer.NotifySession)
	for _, resource := range []string{"applications", "registration-grants", "devices", "connection-grants", "sessions", "audit-events", "relay-nodes", "webhook-endpoints"} {
		api.Handle("/v1/"+resource, managementHandler)
		api.Handle("/v1/"+resource+"/", managementHandler)
	}
	if browserHandler != nil {
		api.Handle("/admin/api/", browserHandler)
		api.Handle("/admin", adminweb.Handler())
		api.Handle("/admin/", adminweb.Handler())
	}
	api.Handle("/v1/device-sessions/", relay.NewHandler(relayService, store))
	api.Handle("/v1/device-signal", signalingServer)
	api.Handle("/", httpapi.New(store))
	postgresReady := database.Ready(pool, migrate.CurrentVersion)
	ready := func(ctx context.Context) error {
		if err := postgresReady(ctx); err != nil {
			return err
		}
		return cache.Ping(ctx).Err()
	}
	handler := httpserver.New(ready, api)
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
		signalingServer.Stop()
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
