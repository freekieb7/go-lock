package model

type Client struct {
	Id           string
	Secret       string
	Name         string
	Confidential bool
	RedirectUris []string
}
