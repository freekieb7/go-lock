package settings

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"strconv"
)

type Environment int

const (
	Production Environment = iota
	Testing
	Development
)

func (e Environment) String() {
}

type Settings struct {
	Environment Environment
	Name        string
	Host        string
	Port        uint16
	DataDir     string
}

func New(ctx context.Context) *Settings {
	var settings Settings

	settings.Environment = Production
	if environment := os.Getenv("environment"); environment != "" {
		switch environment {
		case "production":
			{
				settings.Environment = Production
			}
		case "testing":
			{
				settings.Environment = Testing
			}
		case "development":
			{
				settings.Environment = Development
			}
		default:
			{
				panic(fmt.Sprintf("unknown environment provided %s", environment))
			}
		}
	}

	settings.Name = "go-lock"

	// Host
	settings.Host = "http://localhost:8080"
	if host := os.Getenv("HOST"); host != "" {
		if _, err := url.ParseRequestURI(host); err != nil {
			log.Fatalf("invalid env HOST provided: %s", settings.Host)
		}

		settings.Host = host
	}

	// Port
	settings.Port = 8080
	if port := os.Getenv("PORT"); port != "" {
		strconv.ParseInt(port, 10, 16)
	}

	// DataDir
	if dataDir := os.Getenv("DATA_DIR"); dataDir != "" {
		// Check existing dir
		stat, err := os.Stat(dataDir)
		if err != nil {
			log.Fatal(err)
		}

		if !stat.Mode().IsDir() {
			log.Fatal("DATA_DIR is not a directory")
		}

		settings.DataDir = dataDir
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
