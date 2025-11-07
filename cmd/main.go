package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/freekieb7/go-lock/internal/account"
	"github.com/freekieb7/go-lock/internal/cache"
	"github.com/freekieb7/go-lock/internal/cli"
	"github.com/freekieb7/go-lock/internal/config"
	"github.com/freekieb7/go-lock/internal/database"
	"github.com/freekieb7/go-lock/internal/health"
	"github.com/freekieb7/go-lock/internal/jwks"
	"github.com/freekieb7/go-lock/internal/oauth"
	"github.com/freekieb7/go-lock/internal/session"
	"github.com/freekieb7/go-lock/internal/web/handler"
	"github.com/freekieb7/go-lock/internal/web/handler/api"
	"github.com/freekieb7/go-lock/internal/web/handler/api/shared"
)

func main() {
	ctx := context.Background()

	if err := run(ctx, os.Args); err != nil {
		panic(err)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("  [command]")
		fmt.Println()
		fmt.Println("Commands:")
		fmt.Println("  serve          - Start the web server")
		fmt.Println("  migrate [cmd]  - Run database migrations (up/down)")
		return nil
	}

	switch args[1] {
	case "serve":
		return runServer(ctx)
	case "migrate":
		return runMigrate(ctx, args[1:])
	default:
		return nil
	}
}

func runServer(ctx context.Context) error {
	// Load configuration with proper error handling
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Set logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	db := database.NewDatabase()
	if err := db.Connect(ctx, cfg.Database); err != nil {
		return err
	}
	// Database connection will be properly closed during graceful shutdown

	// Initialize cache system
	var cacheManager *cache.Manager
	if cfg.Cache.Enabled {
		// Create cache configuration
		cacheConfig := &cache.ManagerConfig{
			RedisConfig: &cache.Config{
				Addr:     cfg.Cache.RedisAddr,
				Password: cfg.Cache.RedisPassword,
				DB:       cfg.Cache.RedisDB,
				PoolSize: cfg.Cache.RedisPoolSize,
				Enabled:  true,
			},
			InMemoryTTL:        5 * time.Minute,
			InMemoryMaxSize:    1000,
			CleanupInterval:    1 * time.Minute,
			ClientCacheTTL:     30 * time.Minute,
			UserCacheTTL:       15 * time.Minute,
			PermissionCacheTTL: 10 * time.Minute,
		}

		var err error
		cacheManager, err = cache.NewManager(cacheConfig, logger)
		if err != nil {
			return fmt.Errorf("failed to initialize cache manager: %w", err)
		}

		defer func() {
			if err := cacheManager.Close(); err != nil {
				logger.Error("Failed to close cache manager", "error", err)
			}
		}()
		logger.Info("Cache system initialized", "redis_addr", cfg.Cache.RedisAddr)
	} else {
		logger.Info("Cache system disabled")
	}

	// Initialize services
	baseSessionStore := session.NewStore(&db)
	var sessionStore session.Store = baseSessionStore

	// Wrap with caching if available
	if cacheManager != nil {
		cacheManager.SetSessionStore(baseSessionStore)
	}

	accountService := account.NewService(&db)
	oauthService := oauth.NewService(&db, cacheManager)

	// Initialize JWKS service
	jwksStore := jwks.NewJWKSStore(&db)
	jwksService := jwks.NewJWKSService(jwksStore, logger)

	// Set up JWKS caching if available
	if cacheManager != nil {
		cacheManager.SetJWKSCache()
	}

	// Ensure we have at least one signing key
	if err := jwksService.EnsureSigningKey(ctx); err != nil {
		return fmt.Errorf("failed to ensure signing key: %w", err)
	}

	// Initialize OpenID Connect handler
	baseURL := cfg.GetBaseURL()
	openIDHandler := oauth.NewOpenIDHandler(jwksService, baseURL)

	healthChecker := health.NewChecker(&db, cacheManager, logger)

	// Initialize Handlers
	healthHandler := handler.NewHealthHandler(&healthChecker)

	// Create new API handler using the restructured API
	baseHandler := shared.NewBaseHandler(&cfg, logger, &accountService, &oauthService)
	apiHandler := api.NewHandler(baseHandler)

	uiHandler := handler.NewUIHandler(&cfg, logger, &db, &sessionStore, &accountService, &oauthService)
	oauthHandler := handler.NewOAuthHandler(&cfg, logger, &accountService, &oauthService, &sessionStore, openIDHandler)
	docsHandler := handler.NewDocsHandler()

	// Setup routes
	mux := http.NewServeMux()
	healthHandler.RegisterRoutes(mux)
	apiHandler.RegisterRoutes(mux)
	uiHandler.RegisterRoutes(mux)
	oauthHandler.RegisterRoutes(mux)
	docsHandler.RegisterRoutes(mux)

	// Initialize the web server
	server := &http.Server{
		Addr:           fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:        mux,
		WriteTimeout:   cfg.Server.WriteTimeout,
		ReadTimeout:    cfg.Server.ReadTimeout,
		IdleTimeout:    cfg.Server.IdleTimeout,
		MaxHeaderBytes: cfg.Server.MaxHeaderBytes,
	}

	// Set up signal handling for graceful shutdown
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)

	// Create a channel for server errors
	serverErrChan := make(chan error, 1)

	// Start the server
	go func() {
		logger.InfoContext(ctx, "Starting server", "addr", server.Addr)
		if err := server.ListenAndServe(); err != nil {
			serverErrChan <- err
		}
	}()

	// Wait for termination signal or server error
	select {
	case sig := <-stopChan:
		logger.InfoContext(ctx, "Received shutdown signal", "signal", sig.String())
	case err := <-serverErrChan:
		if err != nil {
			logger.ErrorContext(ctx, "Server error occurred", "error", err)
			return err
		}
	}

	logger.InfoContext(ctx, "Initiating graceful shutdown...")

	// Context with timeout for graceful shutdown (increased to 30 seconds for safety)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown the HTTP server first
	logger.InfoContext(shutdownCtx, "Shutting down HTTP server...")
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.ErrorContext(shutdownCtx, "HTTP server shutdown failed", "error", err)
		// Continue with cleanup even if server shutdown fails
	} else {
		logger.InfoContext(shutdownCtx, "HTTP server stopped successfully")
	}

	// Close database connections
	logger.InfoContext(shutdownCtx, "Closing database connections...")
	db.Close()
	logger.InfoContext(shutdownCtx, "Database connections closed")

	logger.InfoContext(ctx, "Graceful shutdown completed")

	return nil
}

func runMigrate(ctx context.Context, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Set up logger for migrations
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	db := database.NewDatabase()
	if err := db.Connect(ctx, cfg.Database); err != nil {
		return err
	}
	defer db.Close()

	migrator := cli.NewMigrator(&db, logger)
	// Perform migration logic here

	cmd := "help"
	if len(args) >= 2 {
		cmd = args[1]
	}

	switch cmd {
	case "up":
		step := 0
		if len(args) >= 3 {
			var err error
			step, err = strconv.Atoi(args[2])
			if err != nil {
				return fmt.Errorf("invalid step argument: %w", err)
			}
		}

		if err := migrator.MigrateUp(ctx, step); err != nil {
			return err
		}
	case "down":
		step := 0
		if len(args) >= 3 {
			var err error
			step, err = strconv.Atoi(args[2])
			if err != nil {
				return fmt.Errorf("invalid step argument: %w", err)
			}
		}

		if err := migrator.MigrateDown(ctx, step); err != nil {
			return err
		}
	case "help":
		fmt.Println("Usage:")
		fmt.Println("  migrate [command]")
		fmt.Println()
		fmt.Println("Commands:")
		fmt.Println("  migrate up <step>     - Apply migrations")
		fmt.Println("  migrate down <step>   - Rollback migrations")
	default:
		// handle unknown command
		logger.ErrorContext(ctx, "Unknown migration command",
			slog.String("command", strings.Join(args, " ")))
		fmt.Println("Run 'migrate help' for usage.")
	}

	return nil
}
