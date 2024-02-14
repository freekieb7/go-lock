package container

import (
	"github.com/freekieb/go-lock/controller"
	"github.com/freekieb/go-lock/database"
	"github.com/freekieb/go-lock/repository"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/session"
	"github.com/gofiber/template/html/v2"
	"github.com/redis/go-redis/v9"
)

type Container struct {
	App                      *fiber.App
	SessionStore             *session.Store
	AuthenticationController controller.AuthenticationController
	HomeController           controller.HomeController
	ClientController         controller.ClientController
	UserController           controller.UserController
	OAuthController          controller.OAuthController
}

func New() *Container {
	// Data providers
	db := database.New()

	sessionStore := session.New()
	redisClient := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})

	// Repositories
	clientRepository := repository.NewClientRepository(db.Conn())
	userRepository := repository.NewUserRepository(db.Conn())

	// Controllers
	homeController := controller.NewHomeController()
	clientController := controller.NewClientController(clientRepository)
	userController := controller.NewUserController(userRepository)
	authenticationController := controller.NewAuthenticationController(sessionStore, userRepository)
	oauthController := controller.NewOAuthController(sessionStore, clientRepository, redisClient)

	engine := html.New("./view", ".html")
	//engine.Reload(true)

	app := fiber.New(fiber.Config{
		Views: engine,
	})

	return &Container{
		App:                      app,
		SessionStore:             sessionStore,
		AuthenticationController: authenticationController,
		HomeController:           homeController,
		ClientController:         clientController,
		UserController:           userController,
		OAuthController:          oauthController,
	}
}
