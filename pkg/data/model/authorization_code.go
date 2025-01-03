package model

import "github.com/google/uuid"

type AuthorizationCode struct {
	ClientId            uuid.UUID
	UserId              uuid.UUID
	Code                string
	Audience            string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
}
