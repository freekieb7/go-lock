package helpers

import "github.com/freekieb7/go-lock/pkg/jwt"

// Builder provides a fluent API for building JWT tokens
type Builder struct {
	payload map[string]any
}

// NewBuilder creates a new JWT token builder
func NewBuilder() *Builder {
	return &Builder{
		payload: make(map[string]any),
	}
}

// Reset clears all payload claims and returns the builder
func (b *Builder) Reset() *Builder {
	b.payload = make(map[string]any)
	return b
}

// SetIssuer sets the "iss" claim
func (b *Builder) SetIssuer(issuer string) *Builder {
	b.payload["iss"] = issuer
	return b
}

// SetAudience sets the "aud" claim
func (b *Builder) SetAudience(audience string) *Builder {
	b.payload["aud"] = audience
	return b
}

// SetSubject sets the "sub" claim
func (b *Builder) SetSubject(subject string) *Builder {
	b.payload["sub"] = subject
	return b
}

// SetExpiresAt sets the "exp" claim
func (b *Builder) SetExpiresAt(expiresAt int64) *Builder {
	b.payload["exp"] = expiresAt
	return b
}

// SetIssuedAt sets the "iat" claim
func (b *Builder) SetIssuedAt(issuedAt int64) *Builder {
	b.payload["iat"] = issuedAt
	return b
}

// SetNotBefore sets the "nbf" claim
func (b *Builder) SetNotBefore(notBefore int64) *Builder {
	b.payload["nbf"] = notBefore
	return b
}

// SetScope sets the "scope" claim
func (b *Builder) SetScope(scopes string) *Builder {
	b.payload["scope"] = scopes
	return b
}

// SetJTI sets the "jti" (JWT ID) claim
func (b *Builder) SetJTI(id string) *Builder {
	b.payload["jti"] = id
	return b
}

// SetCustomClaim sets a custom claim
func (b *Builder) SetCustomClaim(key string, value any) *Builder {
	b.payload[key] = value
	return b
}

// Build creates a new JWT token with the configured payload
func (b *Builder) Build() jwt.Token {
	token := jwt.NewToken()
	token.Payload = b.payload
	return token
}
