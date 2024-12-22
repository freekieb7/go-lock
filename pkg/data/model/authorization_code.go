package model

import "github.com/freekieb7/go-lock/pkg/uuid"

type AuthorizationCode struct {
	ClientId            string
	UserId              uuid.UUID
	Code                string
	Audience            string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
}
