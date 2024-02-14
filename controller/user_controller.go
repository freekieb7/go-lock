package controller

import (
	"github.com/freekieb/go-lock/model"
	"github.com/freekieb/go-lock/repository"
	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"log"
)

type UserController interface {
	ShowUsers(c fiber.Ctx) error
	CreateUser(c fiber.Ctx) error
}

type userController struct {
	userRepository repository.UserRepository
}

func NewUserController(userRepository repository.UserRepository) UserController {
	return &userController{
		userRepository: userRepository,
	}
}

func (controller *userController) ShowUsers(c fiber.Ctx) error {
	userList, err := controller.userRepository.GetUserList()

	if err != nil {
		return c.SendStatus(500)
	}

	return c.Render("users", fiber.Map{
		"Title": "Users",
		"Users": userList,
	}, "layouts/main")
}

func (controller *userController) CreateUser(c fiber.Ctx) error {
	fEmail := c.FormValue("email")
	fPassword := c.FormValue("password")

	password, err := bcrypt.GenerateFromPassword([]byte(fPassword), bcrypt.DefaultCost)

	if err != nil {
		log.Println(err)
		return c.SendStatus(500)
	}

	err = controller.userRepository.CreateUser(model.User{
		ID:       uuid.New(),
		Email:    fEmail,
		Password: string(password),
	})

	if err != nil {
		log.Println(err)
		return c.SendStatus(500)
	}

	return c.Redirect().To("/clients")
}
