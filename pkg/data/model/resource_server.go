package model

import "github.com/google/uuid"

type SigningAlgorithm string

const (
	SigningAlgorithmRS256 SigningAlgorithm = "RS256" // Asymmetric algorithm
	// SigningAlgorithmHS256 SigningAlgorithm = "HS256" // Symmetric algorithm
)

type ResourceServerType string

const (
	ResourceServerTypeSystemServer = "system"
	ResourceServerTypeCustomServer = "custom"
)

func (t ResourceServerType) UserFriendlyName() string {
	switch t {
	case ResourceServerTypeCustomServer:
		{
			return "Custom"
		}
	case ResourceServerTypeSystemServer:
		{
			return "System"
		}
	}

	return "Unknown"
}

type ResourceServer struct {
	Id                       uuid.UUID
	Name                     string
	Url                      string
	Type                     ResourceServerType
	SigningAlgorithm         SigningAlgorithm
	Scopes                   string
	AllowSkippingUserConsent bool
	CreatedAt                int64
	UpdatedAt                int64
	DeletedAt                int64
}
