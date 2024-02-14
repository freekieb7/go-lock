package controller

import (
	"github.com/freekieb/go-lock/repository"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/session"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
)

type AuthenticationController interface {
	ShowLogin(c fiber.Ctx) error
	ShowAuthorize(c fiber.Ctx) error
	Login(c fiber.Ctx) error
}

type authenticationController struct {
	sessionStore   *session.Store
	userRepository repository.UserRepository
}

func NewAuthenticationController(sessionStore *session.Store, userRepository repository.UserRepository) AuthenticationController {
	return &authenticationController{
		sessionStore:   sessionStore,
		userRepository: userRepository,
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

	formEmail := c.FormValue("email")
	formPassword := c.FormValue("password")

	user, err := controller.userRepository.GetUserByEmail(formEmail)

	if err != nil {
		log.Println(err)
		return c.SendStatus(http.StatusNotFound)
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(formPassword))

	if err != nil {
		log.Println(err)
		return c.SendStatus(http.StatusNotFound)
	}

	sess.Set("UserID", user.ID)
	sess.Save()

	return c.Redirect().Status(http.StatusFound).To("/authorize")
}
