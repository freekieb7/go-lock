package controller

import (
	"github.com/gofiber/fiber/v3"
)

type HomeController interface {
	ShowHome(c fiber.Ctx) error
}

type homeController struct {
}

func NewHomeController() HomeController {
	return &homeController{}
}

func (controller *homeController) ShowHome(c fiber.Ctx) error {
	return c.Render("index", fiber.Map{
		"Title": "Hello, World!",
	}, "layouts/main")
}
