package model

type AccessToken struct {
	ClientId      string
	Token         string
	ExpiresAtDate int64
}
