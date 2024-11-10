package model

type AuthorizationCode struct {
	ClientId      string
	Code          string
	Audience      string
	Scope         string
	CodeChallenge string
}
