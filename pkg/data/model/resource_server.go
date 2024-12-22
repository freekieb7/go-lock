package model

type SigningAlgorithm string

const (
	SigningAlgorithmRS256 SigningAlgorithm = "RS256" // Asymmetric algorithm
	// SigningAlgorithmHS256 SigningAlgorithm = "HS256" // Symmetric algorithm
)

type ResourceServer struct {
	Id               string
	Name             string
	Uri              string
	SigningAlgorithm SigningAlgorithm
	Scopes           []string
}
