package controller

import (
	"github.com/gofiber/fiber/v3"
)

type UserController interface {
	ShowUsers(c fiber.Ctx) error
}

type userController struct {
}

func NewUserController() UserController {
	return &userController{}
}

func (controller *userController) ShowUsers(c fiber.Ctx) error {
	return c.Render("users", fiber.Map{
		"Title": "Users",
	}, "layouts/main")
}
