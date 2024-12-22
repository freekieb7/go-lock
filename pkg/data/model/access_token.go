package model

type AccessToken struct {
	ClientId       string
	Token          string
	ExpirationDate int64
}
