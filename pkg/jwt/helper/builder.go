package helper

import "github.com/freekieb7/go-lock/pkg/jwt"

type JwtBuilder struct {
	payload map[string]any
}

func NewJwtBuilder() *JwtBuilder {
	return &JwtBuilder{
		payload: make(map[string]any),
	}
}

func (builder *JwtBuilder) Reset() *JwtBuilder {
	builder.payload = make(map[string]any)
	return builder
}

func (builder *JwtBuilder) SetIssuer(issuer string) *JwtBuilder {
	builder.payload["iss"] = issuer
	return builder
}

func (builder *JwtBuilder) SetAudience(audience string) *JwtBuilder {
	builder.payload["aud"] = audience
	return builder
}

func (builder *JwtBuilder) SetSubject(subject string) *JwtBuilder {
	builder.payload["sub"] = subject
	return builder
}

func (builder *JwtBuilder) SetExpiresAt(expiresAt int64) *JwtBuilder {
	builder.payload["exp"] = expiresAt
	return builder
}

func (builder *JwtBuilder) SetInitiatedAt(initiatedAt int64) *JwtBuilder {
	builder.payload["iat"] = initiatedAt
	return builder
}

func (builder *JwtBuilder) SetNotBefore(notBefore int64) *JwtBuilder {
	builder.payload["nbf"] = notBefore
	return builder
}

func (builder *JwtBuilder) SetScope(scopes string) *JwtBuilder {
	builder.payload["scope"] = scopes
	return builder
}

func (builder *JwtBuilder) SetId(id string) *JwtBuilder {
	builder.payload["jti"] = id
	return builder
}

func (builder *JwtBuilder) SetCustomClaim(key string, value any) *JwtBuilder {
	builder.payload[key] = value
	return builder
}

func (builder *JwtBuilder) Build() jwt.Token {
	token := jwt.New()
	token.Payload = builder.payload

	return token
}
