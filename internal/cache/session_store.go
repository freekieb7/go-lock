package cache

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/freekieb7/go-lock/internal/session"
)

// SessionStore provides a cached session store using Redis
type SessionStore struct {
	cache      *Service
	baseStore  session.Store
	logger     *slog.Logger
	sessionTTL time.Duration
}

// SessionStoreConfig holds configuration for the cached session store
type SessionStoreConfig struct {
	SessionTTL time.Duration // How long to cache sessions
}

// DefaultSessionStoreConfig returns default configuration
func DefaultSessionStoreConfig() *SessionStoreConfig {
	return &SessionStoreConfig{
		SessionTTL: 30 * time.Minute, // Cache sessions for 30 minutes
	}
}

// NewSessionStore creates a new cached session store
func NewSessionStore(cache *Service, baseStore session.Store, logger *slog.Logger, config *SessionStoreConfig) *SessionStore {
	if config == nil {
		config = DefaultSessionStoreConfig()
	}

	return &SessionStore{
		cache:      cache,
		baseStore:  baseStore,
		logger:     logger,
		sessionTTL: config.SessionTTL,
	}
}

// GetSessionByToken retrieves a session by token, checking cache first
func (s *SessionStore) GetSessionByToken(ctx context.Context, token string) (session.Session, error) {
	cacheKey := s.sessionCacheKey(token)

	// Try cache first
	var cachedSession session.Session
	err := s.cache.Get(ctx, cacheKey, &cachedSession)
	if err == nil {
		s.logger.Debug("Session cache hit", "token", maskToken(token))
		return cachedSession, nil
	}

	if err != ErrCacheMiss {
		s.logger.Warn("Session cache error", "error", err, "token", maskToken(token))
	}

	// Cache miss, get from base store
	sess, err := s.baseStore.GetSessionByToken(ctx, token)
	if err != nil {
		return session.Session{}, err
	}

	// Cache the session (fire and forget)
	go func() {
		if cacheErr := s.cache.Set(context.Background(), cacheKey, sess, s.sessionTTL); cacheErr != nil {
			s.logger.Warn("Failed to cache session", "error", cacheErr, "token", maskToken(token))
		}
	}()

	s.logger.Debug("Session retrieved from database", "token", maskToken(token))
	return sess, nil
}

// SaveSession saves a session and updates the cache
func (s *SessionStore) SaveSession(ctx context.Context, sess session.Session) (session.Session, error) {
	// Save to base store first
	savedSession, err := s.baseStore.SaveSession(ctx, sess)
	if err != nil {
		return session.Session{}, err
	}

	// Update cache (fire and forget)
	cacheKey := s.sessionCacheKey(savedSession.Token)
	go func() {
		if cacheErr := s.cache.Set(context.Background(), cacheKey, savedSession, s.sessionTTL); cacheErr != nil {
			s.logger.Warn("Failed to cache saved session", "error", cacheErr, "token", maskToken(savedSession.Token))
		}
	}()

	s.logger.Debug("Session saved and cached", "token", maskToken(savedSession.Token))
	return savedSession, nil
}

// NewSession creates a new session
func (s *SessionStore) NewSession() (session.Session, error) {
	return s.baseStore.NewSession()
}

// DeleteSession deletes a session from both cache and base store
func (s *SessionStore) DeleteSession(ctx context.Context, token string) error {
	// Delete from base store
	err := s.baseStore.DeleteSession(ctx, token)
	if err != nil {
		return err
	}

	// Delete from cache (fire and forget)
	cacheKey := s.sessionCacheKey(token)
	go func() {
		if cacheErr := s.cache.Delete(context.Background(), cacheKey); cacheErr != nil {
			s.logger.Warn("Failed to delete session from cache", "error", cacheErr, "token", maskToken(token))
		}
	}()

	s.logger.Debug("Session deleted", "token", maskToken(token))
	return nil
}

// InvalidateAllSessions clears all cached sessions (useful for security incidents)
func (s *SessionStore) InvalidateAllSessions(ctx context.Context) error {
	// Clear all session cache entries (pattern delete)
	err := s.cache.DeletePattern(ctx, "session:*")
	if err != nil {
		s.logger.Warn("Failed to clear session cache", "error", err)
		return err
	}

	s.logger.Debug("All session cache cleared")
	return nil
}

// sessionCacheKey generates a cache key for a session token
func (s *SessionStore) sessionCacheKey(token string) string {
	return fmt.Sprintf("session:%s", token)
}

// maskToken masks a token for logging (shows only first 8 characters)
func maskToken(token string) string {
	if len(token) <= 8 {
		return "***"
	}
	return token[:8] + "***"
}
