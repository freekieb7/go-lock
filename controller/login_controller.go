package controller

import (
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/session"
	"log"
	"net/http"
)

type AuthenticationController interface {
	ShowLogin(c fiber.Ctx) error
	ShowAuthorize(c fiber.Ctx) error
	Login(c fiber.Ctx) error
}

type authenticationController struct {
	sessionStore *session.Store
}

func NewAuthenticationController(sessionStore *session.Store) AuthenticationController {
	return &authenticationController{
		sessionStore: sessionStore,
	}
}

func (controller *authenticationController) ShowLogin(c fiber.Ctx) error {
	return c.Render("login", nil)
}

func (controller *authenticationController) ShowAuthorize(c fiber.Ctx) error {
	return c.Render("authorize", nil)
}

func (controller *authenticationController) Login(c fiber.Ctx) error {
	sess, err := controller.sessionStore.Get(c)

	if err != nil {
		log.Println(err)
		return c.SendStatus(http.StatusInternalServerError)
	}

	username := c.FormValue("username")
	password := c.FormValue("password")

	if username != "test" || password != "test" {
		return c.SendStatus(http.StatusNotFound)
	}

	sess.Set("UserID", username)
	sess.Save()

	return c.Redirect().Status(http.StatusFound).To("/authorize")
}
