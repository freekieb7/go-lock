package settings

import (
	"context"
	"errors"
	"log"
	"net/url"
	"os"
	"strconv"
)

type Settings struct {
	Name    string
	Host    string
	Port    uint16
	DataDir string
}

func New(ctx context.Context) *Settings {
	var settings Settings

	settings.Name = "go-lock"

	// Host
	settings.Host = os.Getenv("HOST")
	if settings.Host != "" {
		if _, err := url.ParseRequestURI(settings.Host); err != nil {
			log.Fatalf("invalid env HOST provided: %s", settings.Host)
		}
	} else {
		settings.Host = "http://localhost:8080"
	}

	// Port
	if os.Getenv("PORT") != "" {
		strconv.ParseInt(os.Getenv("PORT"), 10, 16)
	} else {
		settings.Port = 8080
	}

	// DataDir
	settings.DataDir = os.Getenv("DATA_DIR")
	if settings.DataDir != "" {
		// Check existing dir
		stat, err := os.Stat(settings.DataDir)
		if err != nil {
			log.Fatal(err)
		}

		if !stat.Mode().IsDir() {
			log.Fatal("DATA_DIR is not a directory")
		}
	} else {
		// Create tmp dir
		dir, err := os.MkdirTemp(os.TempDir(), "*")
		if err != nil {
			log.Panic(errors.Join(errors.New("create tmp data dir failed"), err))
		}

		if err := os.Chmod(dir, 0777); err != nil {
			log.Panic(errors.Join(errors.New("change tmp data dir mode failed"), err))
		}

		settings.DataDir = dir

		// Cleanup tmp folder
		go func() {
			<-ctx.Done()

			log.Print("tmp data dir removed")

			if err := os.RemoveAll(settings.DataDir); err != nil {
				log.Print(errors.Join(errors.New("removing tmp data dir failed"), err))
			}

			log.Print("tmp data dir removed")
		}()
	}

	return &settings
}
