package controller

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/freekieb/go-lock/database"
	"github.com/freekieb/go-lock/model"
	"github.com/freekieb/go-lock/random"
	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"
	"log"
)

type ClientController interface {
	ShowClients(c fiber.Ctx) error
	ShowClientDetails(c fiber.Ctx) error
	CreateClient(c fiber.Ctx) error
	DeleteClient(c fiber.Ctx) error
	CreateRedirect(c fiber.Ctx) error
}

type clientController struct {
	db database.Db
}

func NewClientController(db database.Db) ClientController {
	return &clientController{
		db: db,
	}
}

func (controller *clientController) ShowClients(c fiber.Ctx) error {
	var clients []model.Client

	rows, err := controller.db.Conn().Query("select id, secret, name from client")

	if err != nil {
		log.Println(err)
		return c.SendStatus(500)
	}

	for rows.Next() {
		var id string
		var name string
		var secret string

		err = rows.Scan(&id, &secret, &name)
		if err != nil {
			log.Fatal(err)
		}

		clients = append(clients, model.Client{
			ID:     id,
			Name:   name,
			Secret: secret,
		})
	}

	// Render index within layouts/main
	return c.Render("clients", fiber.Map{
		"Title":   "Clients",
		"Clients": clients,
	}, "layouts/main")
}

func (controller *clientController) ShowClientDetails(c fiber.Ctx) error {
	clientId := c.Params("client_id")

	var client model.Client
	err := controller.db.Conn().QueryRow(`
		SELECT id, name, secret
		FROM client 
		WHERE id = ?
		LIMIT 1;
		`,
		clientId,
	).Scan(&client.ID, &client.Name, &client.Secret)

	if err != nil {
		log.Println(err)
		return c.SendStatus(500)
	}

	var redirectUris []string
	rows, err := controller.db.Conn().Query(`
		SELECT redirect_uri
		FROM client_redirect
		WHERE client_id = ?;
		`,
		clientId,
	)

	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			log.Println(err)
			return c.SendStatus(500)
		}
	}

	for rows.Next() {
		var redirectUri string
		err := rows.Scan(&redirectUri)

		if err != nil {
			return c.SendStatus(500)
		}

		redirectUris = append(redirectUris, redirectUri)
	}

	return c.Render("client_details", fiber.Map{
		"Title":     "Client details",
		"Client":    client,
		"Redirects": redirectUris,
	}, "layouts/main")
}

func (controller *clientController) CreateClient(c fiber.Ctx) error {
	name := c.FormValue("name")

	stmnt, err := controller.db.Conn().Prepare(`INSERT INTO client (id, name, secret) VALUES (?,?,?);`)

	if err != nil {
		log.Println(err)
		return c.SendStatus(500)
	}

	_, err = stmnt.Exec(uuid.New().String(), name, random.String(10))

	if err != nil {
		log.Println(err)
		return c.SendStatus(500)
	}

	return c.Redirect().To("/clients")
}

func (controller *clientController) DeleteClient(c fiber.Ctx) error {
	id := c.Params("client_id")

	stmnt, err := controller.db.Conn().Prepare(`DELETE FROM client WHERE id = ?`)

	if err != nil {
		log.Println(err)
		return c.SendStatus(500)
	}

	_, err = stmnt.Exec(id)

	if err != nil {
		log.Println(err)
		return c.SendStatus(500)
	}

	c.Status(200)
	return c.Send([]byte(""))
}

func (controller *clientController) CreateRedirect(c fiber.Ctx) error {
	clientId := c.Params("client_id")

	redirect := c.FormValue("redirect")

	_, err := controller.db.Conn().Exec("INSERT INTO client_redirect (id, client_id, redirect_uri) VALUES (?,?,?);", uuid.New(), clientId, redirect)

	if err != nil {
		return c.SendStatus(500)
	}

	return c.Redirect().To(fmt.Sprintf("/clients/%s", clientId))
}
