package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/freekieb7/go-lock/pkg/container"
	"github.com/freekieb7/go-lock/pkg/data/local/migration"
	"github.com/freekieb7/go-lock/pkg/data/local/migration/migrator"
	migration_version "github.com/freekieb7/go-lock/pkg/data/local/migration/versions"
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

	migrator := migrator.New(container.Database)

	if err := migrator.Up(ctx, []migration.Migration{
		migration_version.NewMigrationCreateTables(container.Settings),
	}); err != nil {
		return errors.Join(errors.New("migration up failed"), err)
	}

	// db, err := connectDB(filepath.Join(settings.DataDir, "logs.db"))
	// if err != nil {
	// 	return errors.Join(errors.New("Connect DB failed"), err)
	// }

	// // Cleanup after shutdown signal received
	// context.AfterFunc(ctx, func() {
	// 	log.Println("Shutdown signal received")

	// 	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	// 	defer cancel()

	// 	if err := server.Shutdown(ctx); err != nil {
	// 		return err
	// 	}

	// 	log.Println("Shutdown completed")
	// })

	server := container.HttpServer

	// Serve app
	srvErr := make(chan error, 1)
	go func() {
		log.Printf("Listening and serving on: %s", "http://0.0.0.0:8080")
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
