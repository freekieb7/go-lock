package repository

import (
	"database/sql"
	"fmt"
	"github.com/freekieb/go-lock/model"
	"github.com/google/uuid"
)

type ClientRepository interface {
	GetClient(clientId uuid.UUID) (model.Client, error)
	GetClientList() ([]model.Client, error)
	GetClientRedirectList(clientId uuid.UUID) ([]model.ClientRedirect, error)
}

type clientRepository struct {
	db *sql.DB
}

func NewClientRepository(db *sql.DB) ClientRepository {
	return &clientRepository{
		db: db,
	}
}

func (repository *clientRepository) GetClient(clientId uuid.UUID) (model.Client, error) {
	var client model.Client

	row := repository.db.QueryRow("SELECT id, name, secret FROM client;")

	if err := row.Scan(&client.ID, &client.Name, &client.Secret); err != nil {
		return client, fmt.Errorf("getClient %d: %v", clientId, err)
	}

	return client, nil
}

func (repository *clientRepository) GetClientList() ([]model.Client, error) {
	var clientList []model.Client

	rows, err := repository.db.Query("SELECT id, name, secret FROM client;")

	if err != nil {
		return nil, fmt.Errorf("getClientList: %v", err)
	}

	defer rows.Close()

	for rows.Next() {
		var client model.Client

		if err := rows.Scan(&client.ID, &client.Name, &client.Secret); err != nil {
			return nil, fmt.Errorf("getClientList: %v", err)
		}

		clientList = append(clientList, client)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("getClientList: %v", err)
	}

	return clientList, nil
}

func (repository *clientRepository) GetClientRedirectList(clientId uuid.UUID) ([]model.ClientRedirect, error) {
	var clientRedirectList []model.ClientRedirect

	rows, err := repository.db.Query(`
		SELECT id, client_id, redirect_uri 
		FROM client_redirect 
		WHERE client_id = ?;
		`,
		clientId,
	)

	if err != nil {
		return nil, fmt.Errorf("getClientRedirectList: %v", err)
	}

	defer rows.Close()

	for rows.Next() {
		var clientRedirect model.ClientRedirect

		if err := rows.Scan(&clientRedirect.ID, &clientRedirect.ClientID, &clientRedirect.Uri); err != nil {
			return nil, fmt.Errorf("getClientRedirectList: %v", err)
		}

		clientRedirectList = append(clientRedirectList, clientRedirect)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("getClientRedirectList: %v", err)
	}

	return clientRedirectList, nil
}
