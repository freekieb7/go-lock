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
	"github.com/freekieb7/go-lock/pkg/data/migration"
	"github.com/freekieb7/go-lock/pkg/data/model"
	"github.com/google/uuid"
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

	// Check for admin user
	admins, err := container.UserStore.AllByRole(ctx, model.UserRoleAdmin)
	if err != nil {
		return errors.Join(errors.New("getting app managers failed"), err)
	}

	if len(admins) == 0 {
		email := container.Settings.AdminEmail
		password := container.Settings.AdminPasswordHash
		if email == "" || len(password) == 0 {
			return errors.New("admin email and password required for first time setup")
		}

		now := time.Now().UTC().Unix()
		if err := container.UserStore.Create(ctx, model.User{
			Id:           uuid.New(),
			Email:        container.Settings.AdminEmail,
			PasswordHash: password,
			Role:         model.UserRoleAdmin,
			CreatedAt:    now,
			UpdatedAt:    now,
		}); err != nil {
			return errors.Join(errors.New("admin user could not be created"), err)
		}
	}

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
