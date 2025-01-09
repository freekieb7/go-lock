package generator

import (
	"context"
	"time"

	"github.com/freekieb7/go-lock/pkg/data/store"
	"github.com/freekieb7/go-lock/pkg/jwt"
	"github.com/freekieb7/go-lock/pkg/settings"
	"github.com/google/uuid"
)

type TokenGenerator struct {
	settings  *settings.Settings
	jwksStore *store.JwksStore
}

func NewTokenGenerator(settings *settings.Settings, jwksStore *store.JwksStore) *TokenGenerator {
	return &TokenGenerator{
		settings:  settings,
		jwksStore: jwksStore,
	}
}

func (generator *TokenGenerator) GenerateAccessToken(ctx context.Context, userId uuid.UUID, audience string, scope string) (string, float64, error) {
	jwkSets, err := generator.jwksStore.All(ctx)
	if err != nil {
		return "", 0, err
	}

	if len(jwkSets) < 1 {
		return "", 0, err
	}

	jwks := jwkSets[len(jwkSets)-1] // Take last

	privateKey, err := jwt.ParseRsaPrivateKey(jwks.PrivateKey)
	if err != nil {
		return "", 0, err
	}

	now := time.Now().UTC()
	expiresIn := time.Hour
	payload := map[string]any{
		"iss": generator.settings.Host,
		"sub": userId.String(),
		"exp": now.Add(expiresIn).Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"aud": audience,
	}

	if scope != "" {
		payload["scope"] = scope
	}

	token := jwt.Token{
		Header: map[string]any{
			"kid": jwks.Id,
		},
		Payload: payload,
	}

	signedToken, err := jwt.Encode(token, privateKey)
	if err != nil {
		return "", 0, err
	}

	return signedToken, expiresIn.Seconds(), nil
}
