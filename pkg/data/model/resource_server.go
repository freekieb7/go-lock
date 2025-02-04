package model

import "github.com/google/uuid"

type SigningAlgorithm string

const (
	SigningAlgorithmRS256 SigningAlgorithm = "RS256" // Asymmetric algorithm
	// SigningAlgorithmHS256 SigningAlgorithm = "HS256" // Symmetric algorithm
)

type ResourceServer struct {
	Id                       uuid.UUID
	Name                     string
	Description              string
	Url                      string
	IsSystem                 bool
	SigningAlgorithm         SigningAlgorithm
	AllowSkippingUserConsent bool
	AllowOfflineAccess       bool
	Scopes                   []ResourceServerScope
	CreatedAt                int64
	UpdatedAt                int64
}

type ResourceServerScope struct {
	Value       string
	Description string
}
