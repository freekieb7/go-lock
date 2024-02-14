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
	CreateClient(client model.Client) error
	DeleteClient(clientId uuid.UUID) error
	GetClientCallbackList(clientId uuid.UUID) ([]model.ClientCallback, error)
	CreateClientCallback(clientRedirect model.ClientCallback) error
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

	row := repository.db.QueryRow("SELECT id, name, secret FROM tbl_client;")

	if err := row.Scan(&client.ID, &client.Name, &client.Secret); err != nil {
		return client, fmt.Errorf("getClient %d: %v", clientId, err)
	}

	return client, nil
}

func (repository *clientRepository) GetClientList() ([]model.Client, error) {
	var clientList []model.Client

	rows, err := repository.db.Query("SELECT id, name, secret FROM tbl_client;")

	if err != nil {
		return nil, fmt.Errorf("GetClientList: %v", err)
	}

	defer rows.Close()

	for rows.Next() {
		var client model.Client

		if err := rows.Scan(&client.ID, &client.Name, &client.Secret); err != nil {
			return nil, fmt.Errorf("GetClientList: %v", err)
		}

		clientList = append(clientList, client)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetClientList: %v", err)
	}

	return clientList, nil
}

func (repository *clientRepository) CreateClient(client model.Client) error {
	_, err := repository.db.Exec(
		"INSERT INTO tbl_client (id, name, secret) VALUES (?,?,?);",
		client.ID, client.Name, client.Secret,
	)

	return err
}

func (repository *clientRepository) DeleteClient(clientId uuid.UUID) error {
	_, err := repository.db.Exec("DELETE FROM tbl_client WHERE id = ?;", clientId)

	return err
}

func (repository *clientRepository) GetClientCallbackList(clientId uuid.UUID) ([]model.ClientCallback, error) {
	var clientRedirectList []model.ClientCallback

	rows, err := repository.db.Query(
		"SELECT id, client_id, uri FROM tbl_client_callback WHERE client_id = ?;",
		clientId,
	)

	if err != nil {
		return nil, fmt.Errorf("GetClientRedirectList: %v", err)
	}

	defer rows.Close()

	for rows.Next() {
		var clientCallback model.ClientCallback

		if err := rows.Scan(&clientCallback.ID, &clientCallback.ClientID, &clientCallback.Uri); err != nil {
			return nil, fmt.Errorf("GetClientRedirectList: %v", err)
		}

		clientRedirectList = append(clientRedirectList, clientCallback)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetClientRedirectList: %v", err)
	}

	return clientRedirectList, nil
}

func (repository *clientRepository) CreateClientCallback(clientCallback model.ClientCallback) error {
	_, err := repository.db.Exec(
		"INSERT INTO tbl_client_callback (id, client_id, uri) VALUES (?,?,?);",
		clientCallback.ID, clientCallback.ClientID, clientCallback.Uri,
	)

	return err
}
