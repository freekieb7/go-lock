package controller

import (
	"fmt"
	"github.com/freekieb/go-lock/model"
	"github.com/freekieb/go-lock/random"
	"github.com/freekieb/go-lock/repository"
	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"log"
)

type ClientController interface {
	ShowClients(c fiber.Ctx) error
	ShowClientDetails(c fiber.Ctx) error
	CreateClient(c fiber.Ctx) error
	DeleteClient(c fiber.Ctx) error
	CreateCallback(c fiber.Ctx) error
}

type clientController struct {
	clientRepository repository.ClientRepository
}

func NewClientController(clientRepository repository.ClientRepository) ClientController {
	return &clientController{
		clientRepository: clientRepository,
	}
}

func (controller *clientController) ShowClients(c fiber.Ctx) error {
	clientList, err := controller.clientRepository.GetClientList()

	if err != nil {
		return c.SendStatus(500)
	}

	// Render index within layouts/main
	return c.Render("clients", fiber.Map{
		"Title":   "Clients",
		"Clients": clientList,
	}, "layouts/main")
}

func (controller *clientController) ShowClientDetails(c fiber.Ctx) error {
	paramClientId := c.Params("client_id")

	clientId, err := uuid.Parse(paramClientId)

	if err != nil {
		log.Println(err)
		return c.SendStatus(500)
	}

	client, err := controller.clientRepository.GetClient(clientId)

	if err != nil {
		log.Println(err)
		return c.SendStatus(500)
	}

	callbackList, err := controller.clientRepository.GetClientCallbackList(clientId)

	if err != nil {
		log.Println(err)
		return c.SendStatus(500)
	}

	return c.Render("client_details", fiber.Map{
		"Title":        "Client details",
		"Client":       client,
		"CallbackList": callbackList,
	}, "layouts/main")
}

func (controller *clientController) CreateClient(c fiber.Ctx) error {
	formName := c.FormValue("name")

	client := model.Client{
		ID:     uuid.New(),
		Name:   formName,
		Secret: random.String(10),
	}

	err := controller.clientRepository.CreateClient(client)

	if err != nil {
		log.Println(err)
		return c.SendStatus(500)
	}

	return c.Redirect().To("/clients")
}

func (controller *clientController) DeleteClient(c fiber.Ctx) error {
	reqClientId := c.Params("client_id")

	clientId, err := uuid.Parse(reqClientId)

	if err != nil {
		log.Println(err)
		return c.SendStatus(500)
	}

	err = controller.clientRepository.DeleteClient(clientId)

	if err != nil {
		log.Println(err)
		return c.SendStatus(500)
	}

	return c.SendStatus(200)
}

func (controller *clientController) CreateCallback(c fiber.Ctx) error {
	paramClientId := c.Params("client_id")
	formCallback := c.FormValue("callback")

	clientId, err := uuid.Parse(paramClientId)

	if err != nil {
		log.Println(err)
		return c.SendStatus(400)
	}

	err = controller.clientRepository.CreateClientCallback(model.ClientCallback{
		ID:       uuid.New(),
		ClientID: clientId,
		Uri:      formCallback,
	})

	if err != nil {
		log.Println(err)
		return c.SendStatus(400)
	}

	return c.Redirect().To(fmt.Sprintf("/clients/%s", clientId))
}
