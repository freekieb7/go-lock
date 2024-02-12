package main

import (
	"github.com/freekieb/go-lock/container"
	"github.com/gofiber/fiber/v3/middleware/logger"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	c := container.New()

	// Middleware
	c.App.Use(logger.New())

	// Server static/public assets
	c.App.Static("/", "./public")

	// Page routes
	c.App.Get("/", c.HomeController.ShowHome)
	c.App.Get("/login", c.AuthenticationController.ShowLogin)
	c.App.Get("/authorize", c.AuthenticationController.ShowAuthorize)
	c.App.Get("/clients", c.ClientController.ShowClients)
	c.App.Get("/clients/:client_id", c.ClientController.ShowClientDetails)
	c.App.Get("/users", c.UserController.ShowUsers)

	// Api routes
	c.App.Post("/api/login", c.AuthenticationController.Login)
	c.App.Post("/api/clients", c.ClientController.CreateClient)
	c.App.Delete("/api/clients/:client_id", c.ClientController.DeleteClient)
	c.App.Post("/api/clients/:client_id/redirects", c.ClientController.CreateRedirect)

	c.App.Get("/api/oauth/authorize", c.OAuthController.ShowAuthorize)
	c.App.Post("/api/oauth/authorize", c.OAuthController.ProcessAuthorize)
	c.App.Post("/api/oauth/token", c.OAuthController.GenerateToken)

	c.App.Listen("0.0.0.0:3000")
}
