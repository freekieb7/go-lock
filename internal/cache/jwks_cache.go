package cache

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/freekieb7/go-lock/internal/jwks"
)

// JWKSCache provides caching for JSON Web Key Sets
type JWKSCache struct {
	cache  *Service
	logger *slog.Logger
	ttl    time.Duration
}

// NewJWKSCache creates a new JWKS cache
func NewJWKSCache(cache *Service, logger *slog.Logger) *JWKSCache {
	return &JWKSCache{
		cache:  cache,
		logger: logger,
		ttl:    24 * time.Hour, // Cache JWKS for 24 hours
	}
}

// GetJWKS retrieves cached JWKS or calls the provided function to generate it
func (c *JWKSCache) GetJWKS(ctx context.Context, issuer string, generateFn func() (*jwks.JWKSet, error)) (*jwks.JWKSet, error) {
	cacheKey := fmt.Sprintf("jwks:%s", issuer)

	var jwkSet jwks.JWKSet
	err := c.cache.GetOrSet(ctx, cacheKey, &jwkSet, c.ttl, func() (interface{}, error) {
		c.logger.Debug("Generating fresh JWKS", "issuer", issuer)
		return generateFn()
	})

	if err != nil {
		return nil, err
	}

	return &jwkSet, nil
}

// InvalidateJWKS removes JWKS from cache (useful when keys are rotated)
func (c *JWKSCache) InvalidateJWKS(ctx context.Context, issuer string) error {
	cacheKey := fmt.Sprintf("jwks:%s", issuer)
	return c.cache.Delete(ctx, cacheKey)
}

// InvalidateAllJWKS removes all JWKS from cache
func (c *JWKSCache) InvalidateAllJWKS(ctx context.Context) error {
	return c.cache.DeletePattern(ctx, "jwks:*")
}
