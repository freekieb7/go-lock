package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/freekieb7/go-lock/pkg/core/container"
	"github.com/freekieb7/go-lock/pkg/core/http/handler"
	"github.com/freekieb7/go-lock/pkg/core/migration"
)

func main() {
	ctx := context.Background()

	if err := Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func Run(ctx context.Context) error {
	// Add gracefull shutdown support by listening for interuptions
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()

	// Create settings
	container := container.New(ctx)
	defer container.Database.Close()

	migrator := migration.NewMigrator(container.Database)
	if err := migrator.Up(ctx); err != nil {
		return errors.Join(errors.New("migration up failed"), err)
	}

	addr := fmt.Sprintf("0.0.0.0:%d", container.Settings.Port)
	server := &http.Server{
		Addr:    addr,
		Handler: handler.New(container),
	}

	// Serve app
	srvErr := make(chan error, 1)
	go func() {
		log.Printf("Listening and serving on: %s", fmt.Sprintf(":%d", container.Settings.Port))
		srvErr <- server.ListenAndServe()
	}()

	// Wait for interruption.
	select {
	case err := <-srvErr:
		// Error when starting HTTP server.
		return err
	case <-ctx.Done():
		// Cleanup afer shutdown signalled
		log.Println("Shutdown signal received")

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			return err
		}

		log.Println("Shutdown completed")
	}

	return nil
}
