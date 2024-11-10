package model

type Client struct {
	Id           string
	Secret       []byte
	Name         string
	Confidential bool
}
