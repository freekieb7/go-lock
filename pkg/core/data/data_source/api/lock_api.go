package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type LockApi struct {
	Url string
}

func NewLockApi(url string) *LockApi {
	return &LockApi{
		Url: url,
	}
}

type GetClientsRequestBody struct {
	Limit  uint8 `json:"limit"`
	Offset uint8 `json:"offset"`
}

type GetClientsResponseBody struct {
	Clients []struct {
		Id   string `json:"id"`
		Name string `json:"name"`
		Type string `json:"type"`
	}
}

func (api *LockApi) GetClients(accessToken string, reqBody GetClientsRequestBody) (GetClientsResponseBody, error) {
	var resBody GetClientsResponseBody

	payload, _ := json.Marshal(reqBody)
	req, err := http.NewRequest(http.MethodGet, api.Url+"/clients", bytes.NewBuffer(payload))
	if err != nil {
		return resBody, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return resBody, err
	}
	defer res.Body.Close()

	if err := json.NewDecoder(res.Body).Decode(&resBody.Clients); err != nil {
		return resBody, err
	}

	return resBody, nil
}

type CreateClientRequestBody struct {
	Name string `json:"name"`
}

type CreateClientResponseBody struct {
	Id string `json:"id"`
}

func (api *LockApi) CreateClient(accessToken string, reqBody CreateClientRequestBody) (CreateClientResponseBody, error) {
	var resBody CreateClientResponseBody

	payload, _ := json.Marshal(reqBody)
	req, err := http.NewRequest(http.MethodPost, api.Url+"/clients", bytes.NewBuffer(payload))
	if err != nil {
		return resBody, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return resBody, err
	}
	defer res.Body.Close()

	if err := json.NewDecoder(res.Body).Decode(&resBody); err != nil {
		return resBody, err
	}

	return resBody, nil
}
