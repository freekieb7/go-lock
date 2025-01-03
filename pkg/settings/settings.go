package settings

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/mail"
	"net/url"
	"os"
	"strconv"

	"golang.org/x/crypto/bcrypt"
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
	Environment       Environment
	Name              string
	Host              string
	Port              uint16
	DataDir           string
	AdminEmail        string
	AdminPasswordHash []byte
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

	adminEmailRaw := os.Getenv("ADMIN_EMAIL")
	if settings.AdminEmail != "" {
		if _, err := mail.ParseAddress(settings.DataDir); err != nil {
			log.Panic(errors.Join(errors.New("admin email is invalid"), err))
		}
	}
	settings.AdminEmail = adminEmailRaw

	adminPasswordRaw := os.Getenv("ADMIN_PASSWORD")
	if adminPasswordRaw == "" {
		log.Panic(errors.New("admin password is invalid"))
	}
	adminPasswordHash, err := bcrypt.GenerateFromPassword([]byte(adminPasswordRaw), bcrypt.DefaultCost)
	if err != nil {
		log.Panic(errors.Join(errors.New("admin password encryption failed"), err))
	}
	settings.AdminPasswordHash = adminPasswordHash

	return &settings
}
