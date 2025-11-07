package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/freekieb7/go-lock/internal/account"
	"github.com/freekieb7/go-lock/internal/cache"
	"github.com/freekieb7/go-lock/internal/database"
	apperrors "github.com/freekieb7/go-lock/internal/errors"
	"github.com/freekieb7/go-lock/internal/oauth/domain"
	"github.com/freekieb7/go-lock/internal/oauth/service"
	"github.com/freekieb7/go-lock/internal/util"
	"github.com/freekieb7/go-lock/pkg/jwt"
	"github.com/freekieb7/go-lock/pkg/jwt/helpers"
	"github.com/google/uuid"
)

var (
	// Deprecated: Use apperrors.NotFoundError instead
	ErrResourceServerNotFound = apperrors.NotFoundError("resource server not found", nil)
	ErrScopeNotFound          = apperrors.NotFoundError("scope not found", nil)
	// Re-exported errors from sub-services for backward compatibility
	ErrRefreshTokenNotFound = service.ErrRefreshTokenNotFound
	ErrRefreshTokenExpired  = service.ErrRefreshTokenExpired
)

// Service provides OAuth operations with Kubernetes-compatible caching.
//
// Caching Strategy for Kubernetes:
// - Redis (L2): Distributed cache shared across all pods (TTL: 2 hours)
//   - Ensures consistency when scaling horizontally
//   - Persists across pod restarts and deployments
//   - Primary source of truth for cached data
//
// - In-Memory (L1): Pod-local cache for performance (TTL: 5 minutes)
//   - Reduces Redis roundtrips for frequently accessed data
//   - Automatically managed by cache.Manager cleanup
//   - Shorter TTL prevents stale data in multi-pod scenarios
//
// - Cache Invalidation: Immediate invalidation across all layers
//   - Uses async goroutines for performance (fire-and-forget)
//   - Ensures cache consistency on data mutations
//   - Clears both Redis and memory simultaneously
type Service struct {
	DB                  *database.Database
	Cache               *cache.Manager
	AccessTokenService  *service.AccessTokenService
	RefreshTokenService *service.RefreshTokenService
}

func NewService(db *database.Database, cacheManager *cache.Manager) Service {
	return Service{
		DB:                  db,
		Cache:               cacheManager,
		AccessTokenService:  service.NewAccessTokenService(db),
		RefreshTokenService: service.NewRefreshTokenService(db),
	}
}

// Cache key management for Kubernetes-compatible distributed caching
func (s *Service) getResourceServerCacheKey(identifier string) string {
	return fmt.Sprintf("oauth:resource_server:%s", identifier)
}

func (s *Service) invalidateResourceServerCache(resourceServer domain.ResourceServer) {
	// Invalidate both ID and URL based cache entries
	idKey := s.getResourceServerCacheKey(fmt.Sprintf("id:%s", resourceServer.ID))
	urlKey := s.getResourceServerCacheKey(fmt.Sprintf("url:%s", resourceServer.URL))

	// Clear both memory and Redis (fire and forget for performance)
	go func() {
		ctx := context.Background()
		s.Cache.DeleteInMemory(idKey)
		s.Cache.DeleteInMemory(urlKey)
		s.Cache.Redis().Delete(ctx, idKey)
		s.Cache.Redis().Delete(ctx, urlKey)
	}()
}

func (s *Service) cacheResourceServer(ctx context.Context, resourceServer domain.ResourceServer) {
	if s.Cache == nil {
		return
	}

	idKey := s.getResourceServerCacheKey(fmt.Sprintf("id:%s", resourceServer.ID))
	urlKey := s.getResourceServerCacheKey(fmt.Sprintf("url:%s", resourceServer.URL))

	// Prepare cache data for Redis (JSON serializable)
	cacheData := map[string]interface{}{
		"id":          resourceServer.ID.String(),
		"url":         resourceServer.URL,
		"description": resourceServer.Description,
		"scopes":      resourceServer.Scopes,
	}

	// Cache in Redis first for distributed consistency (longer TTL)
	s.Cache.Redis().Set(ctx, idKey, cacheData, time.Hour*2) // 2 hours for distributed cache
	s.Cache.Redis().Set(ctx, urlKey, cacheData, time.Hour*2)

	// Cache in memory for performance (shorter TTL for K8s resource efficiency)
	s.Cache.SetInMemory(idKey, resourceServer) // 5 minutes default from manager config
	s.Cache.SetInMemory(urlKey, resourceServer)
}

func (s *Service) NewResourceServer(url, description string, scopes map[string]string) (domain.ResourceServer, error) {
	if url == "" {
		return domain.ResourceServer{}, apperrors.ValidationError("URL cannot be empty", nil)
	}

	id, err := uuid.NewV7()
	if err != nil {
		return domain.ResourceServer{}, apperrors.InternalError("failed to generate UUID", err)
	}

	return domain.ResourceServer{
		ID:          id,
		URL:         url,
		Description: description,
		Scopes:      scopes,
	}, nil
}

func (s *Service) GetResourceServerByID(ctx context.Context, id uuid.UUID) (domain.ResourceServer, error) {
	cacheKey := s.getResourceServerCacheKey(fmt.Sprintf("id:%s", id.String()))

	// Kubernetes-compatible caching: Redis-first for shared state
	if s.Cache != nil {
		// Try Redis first (distributed cache for multi-pod consistency)
		var cachedData map[string]interface{}
		if err := s.Cache.Redis().Get(ctx, cacheKey, &cachedData); err == nil {
			var resourceServer domain.ResourceServer
			// Convert cached data back to domain object
			if idStr, ok := cachedData["id"].(string); ok {
				if parsedID, err := uuid.Parse(idStr); err == nil {
					resourceServer.ID = parsedID
				}
			}
			if url, ok := cachedData["url"].(string); ok {
				resourceServer.URL = url
			}
			if desc, ok := cachedData["description"].(string); ok {
				resourceServer.Description = desc
			}
			if scopes, ok := cachedData["scopes"].(map[string]interface{}); ok {
				resourceServer.Scopes = make(map[string]string)
				for k, v := range scopes {
					if s, ok := v.(string); ok {
						resourceServer.Scopes[k] = s
					}
				}
			}

			// Cache briefly in memory for performance (short TTL for K8s compatibility)
			s.Cache.SetInMemory(cacheKey, resourceServer)
			return resourceServer, nil
		}
	}

	var resourceServer domain.ResourceServer

	query := `
		SELECT resource_server.id, resource_server.url, resource_server.description, jsonb_object_agg(scope.name, scope.description) scopes
		FROM tbl_resource_server resource_server 
		JOIN tbl_scope scope ON resource_server.id = scope.resource_server_id
		WHERE resource_server.id = $1
		GROUP BY resource_server.id
	`

	row := s.DB.QueryRow(ctx, query, id)
	if err := row.Scan(&resourceServer.ID, &resourceServer.URL, &resourceServer.Description, &resourceServer.Scopes); err != nil {
		if errors.Is(err, database.ErrNoRows) {
			return domain.ResourceServer{}, apperrors.NotFoundError("resource server not found", err)
		}
		return domain.ResourceServer{}, apperrors.DatabaseError("failed to get resource server by ID", err)
	}

	// Cache the result using Kubernetes-compatible helper
	s.cacheResourceServer(ctx, resourceServer)

	return resourceServer, nil
}

func (s *Service) GetResourceServerByURL(ctx context.Context, url string) (domain.ResourceServer, error) {
	cacheKey := s.getResourceServerCacheKey(fmt.Sprintf("url:%s", url))

	// Kubernetes-compatible caching: Redis-first for shared state
	if s.Cache != nil {
		// Try Redis first (distributed cache for multi-pod consistency)
		var cachedData map[string]interface{}
		if err := s.Cache.Redis().Get(ctx, cacheKey, &cachedData); err == nil {
			var resourceServer domain.ResourceServer
			// Convert cached data back to domain object
			if idStr, ok := cachedData["id"].(string); ok {
				if parsedID, err := uuid.Parse(idStr); err == nil {
					resourceServer.ID = parsedID
				}
			}
			if cachedURL, ok := cachedData["url"].(string); ok {
				resourceServer.URL = cachedURL
			}
			if desc, ok := cachedData["description"].(string); ok {
				resourceServer.Description = desc
			}
			if scopes, ok := cachedData["scopes"].(map[string]interface{}); ok {
				resourceServer.Scopes = make(map[string]string)
				for k, v := range scopes {
					if s, ok := v.(string); ok {
						resourceServer.Scopes[k] = s
					}
				}
			}

			// Cache briefly in memory for performance (short TTL for K8s compatibility)
			s.Cache.SetInMemory(cacheKey, resourceServer)
			return resourceServer, nil
		}
	}

	var resourceServer domain.ResourceServer

	query := `
		SELECT resource_server.id, resource_server.url, resource_server.description, jsonb_object_agg(scope.name, scope.description) scopes
		FROM tbl_resource_server resource_server 
		JOIN tbl_scope scope ON resource_server.id = scope.resource_server_id
		WHERE url = $1
		GROUP BY resource_server.id
	`
	row := s.DB.QueryRow(ctx, query, url)
	if err := row.Scan(&resourceServer.ID, &resourceServer.URL, &resourceServer.Description, &resourceServer.Scopes); err != nil {
		if errors.Is(err, database.ErrNoRows) {
			return domain.ResourceServer{}, apperrors.NotFoundError("resource server not found", err)
		}
		return domain.ResourceServer{}, apperrors.DatabaseError("failed to get resource server by URL", err)
	}

	// Cache the result using Kubernetes-compatible helper
	s.cacheResourceServer(ctx, resourceServer)

	return resourceServer, nil
}

func (s *Service) CreateResourceServer(ctx context.Context, resourceServer domain.ResourceServer) (domain.ResourceServer, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return domain.ResourceServer{}, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	if err := tx.QueryRow(ctx, `INSERT INTO tbl_resource_server (url, description) VALUES ($1, $2) RETURNING id, created_at`, resourceServer.URL, resourceServer.Description).Scan(&resourceServer.ID, &resourceServer.CreatedAt); err != nil {
		return domain.ResourceServer{}, fmt.Errorf("failed to create resource server: %w", err)
	}

	for name, desc := range resourceServer.Scopes {
		// Ensure scope name is prefixed with resource server URL
		if !strings.HasPrefix(name, resourceServer.URL) {
			return domain.ResourceServer{}, fmt.Errorf("scope name %s must be prefixed with resource server URL %s", name, resourceServer.URL)
		}

		if _, err := tx.Exec(ctx, `INSERT INTO tbl_scope (resource_server_id, name, description) VALUES ($1, $2, $3)`, resourceServer.ID, name, desc); err != nil {
			return domain.ResourceServer{}, fmt.Errorf("failed to create resource server scope: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.ResourceServer{}, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Cache the newly created resource server
	s.cacheResourceServer(ctx, resourceServer)

	return resourceServer, nil
}

func (s *Service) UpdateResourceServer(ctx context.Context, resourceServer domain.ResourceServer) (domain.ResourceServer, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return domain.ResourceServer{}, apperrors.DatabaseError("failed to begin transaction", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `UPDATE tbl_resource_server SET description = $1 WHERE id = $2`, resourceServer.Description, resourceServer.ID); err != nil {
		return domain.ResourceServer{}, apperrors.DatabaseError("failed to update resource server", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return domain.ResourceServer{}, apperrors.DatabaseError("failed to commit transaction", err)
	}

	// Invalidate and refresh cache (Kubernetes: update all pods)
	if s.Cache != nil {
		// Invalidate old cache entries across all pods
		s.invalidateResourceServerCache(resourceServer)

		// Cache updated data immediately using helper
		s.cacheResourceServer(ctx, resourceServer)
	}

	return resourceServer, nil
}

func (s *Service) DeleteResourceServerByID(ctx context.Context, id uuid.UUID) error {
	// Get resource server URL for cache invalidation (Kubernetes: clear from all pods)
	var url string
	if s.Cache != nil {
		err := s.DB.QueryRow(ctx, `SELECT url FROM tbl_resource_server WHERE id = $1`, id).Scan(&url)
		if err != nil {
			// If we can't get URL, continue with deletion but log warning
			url = ""
		}
	}

	if _, err := s.DB.Exec(ctx, `DELETE FROM tbl_resource_server WHERE id = $1`, id); err != nil {
		return apperrors.DatabaseError("failed to delete resource server", err)
	}

	// Invalidate cache in all pods (Kubernetes-compatible)
	if s.Cache != nil {
		// Use helper function for consistent cache invalidation
		resourceServer := domain.ResourceServer{
			ID:  id,
			URL: url,
		}
		s.invalidateResourceServerCache(resourceServer)
	}

	return nil
}

type ListResourceServersParams struct {
	PageSize int
	Token    string
}

type ListResourceServersResult struct {
	ResourceServers []domain.ResourceServer
	NextToken       string
	PrevToken       string
}

type ListResourceServersCursor struct {
	CreatedAt time.Time `json:"created_at"`
	ID        uuid.UUID `json:"id"`
	Direction string    `json:"direction"`
}

func (s *Service) ListResourceServers(ctx context.Context, params ListResourceServersParams) (ListResourceServersResult, error) {
	// Set default page size if invalid
	if params.PageSize <= 0 {
		return ListResourceServersResult{}, fmt.Errorf("page size must be greater than zero")
	}

	cursor, err := decodeListResourceServersCursor(params.Token)
	if err != nil {
		return ListResourceServersResult{}, fmt.Errorf("invalid pagination token: %w", err)
	}

	// Extract direction from cursor, default to "next" for first page
	direction := "next"
	if cursor.Direction != "" {
		direction = cursor.Direction
	}

	query := `
		SELECT rs.id, rs.url, rs.description, rs.created_at, jsonb_object_agg(sc.name, sc.description) scopes
		FROM tbl_resource_server rs 
		JOIN tbl_scope sc ON rs.id = sc.resource_server_id
	`
	args := []any{}
	argIdx := 1

	order := "DESC"
	cmp := "<"

	if direction == "prev" {
		order = "ASC"
		cmp = ">"
	}

	if cursor.ID != uuid.Nil {
		query += fmt.Sprintf("WHERE (rs.created_at, rs.id) %s ($%d, $%d) ", cmp, argIdx, argIdx+1)
		args = append(args, cursor.CreatedAt, cursor.ID)
		argIdx += 2
	}
	query += "GROUP BY rs.id "
	query += fmt.Sprintf("ORDER BY rs.created_at %s, rs.id %s ", order, order)
	query += fmt.Sprintf("LIMIT $%d", argIdx)
	args = append(args, params.PageSize+1) // Fetch one extra to detect more pages

	rows, err := s.DB.Query(ctx, query, args...)
	if err != nil {
		return ListResourceServersResult{}, fmt.Errorf("failed to query resource servers: %w", err)
	}
	defer rows.Close()

	resourceServers := make([]domain.ResourceServer, 0, params.PageSize+1)
	for rows.Next() {
		var resourceServer domain.ResourceServer
		if err := rows.Scan(&resourceServer.ID, &resourceServer.URL, &resourceServer.Description, &resourceServer.CreatedAt, &resourceServer.Scopes); err != nil {
			return ListResourceServersResult{}, fmt.Errorf("failed to scan resource server: %w", err)
		}
		resourceServers = append(resourceServers, resourceServer)
	}

	if len(resourceServers) == 0 {
		return ListResourceServersResult{
			ResourceServers: resourceServers,
		}, nil
	}

	if len(resourceServers) == 0 {
		return ListResourceServersResult{
			ResourceServers: resourceServers,
		}, nil
	}

	// Check if we have more results than requested (indicates more pages)
	hasMore := len(resourceServers) > params.PageSize
	if hasMore {
		resourceServers = resourceServers[:params.PageSize] // Remove the extra record
	}

	// If fetching previous page, reverse results to maintain order
	if direction == "prev" {
		for i, j := 0, len(resourceServers)-1; i < j; i, j = i+1, j-1 {
			resourceServers[i], resourceServers[j] = resourceServers[j], resourceServers[i]
		}
	}

	// Generate next/prev tokens based on actual data availability
	var nextCursor, prevCursor string

	if len(resourceServers) > 0 {
		// Generate next token (for older records)
		showNext := (direction == "next" && hasMore) || (direction == "prev")
		if showNext {
			if nextCursorStr, err := encodeListResourceServersCursor(ListResourceServersCursor{
				ID:        resourceServers[len(resourceServers)-1].ID,
				CreatedAt: resourceServers[len(resourceServers)-1].CreatedAt,
				Direction: "next",
			}); err == nil {
				nextCursor = nextCursorStr
			}
		}

		// Generate prev token (for newer records)
		showPrev := (direction == "prev" && hasMore) || (direction == "next" && params.Token != "")
		if showPrev {
			if prevCursorStr, err := encodeListResourceServersCursor(ListResourceServersCursor{
				ID:        resourceServers[0].ID,
				CreatedAt: resourceServers[0].CreatedAt,
				Direction: "prev",
			}); err == nil {
				prevCursor = prevCursorStr
			}
		}
	}

	return ListResourceServersResult{
		ResourceServers: resourceServers,
		NextToken:       nextCursor,
		PrevToken:       prevCursor,
	}, nil
}

func encodeListResourceServersCursor(cursor ListResourceServersCursor) (string, error) {
	data, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func decodeListResourceServersCursor(token string) (ListResourceServersCursor, error) {
	if token == "" {
		return ListResourceServersCursor{}, nil
	}
	data, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return ListResourceServersCursor{}, err
	}
	var cursor ListResourceServersCursor
	err = json.Unmarshal(data, &cursor)
	return cursor, err
}

func (s *Service) NewAccessToken(clientID, accountID uuid.UUID, scopes []string) (domain.AccessToken, error) {
	return s.AccessTokenService.NewAccessToken(clientID, accountID, scopes)
}

func (s *Service) SaveAccessToken(ctx context.Context, accessToken domain.AccessToken, expiresIn uint32) (domain.AccessToken, error) {
	return s.AccessTokenService.SaveAccessToken(ctx, accessToken, expiresIn)
}

func (s *Service) AssignScopesToClient(ctx context.Context, clientID uuid.UUID, scopes []string) error {
	// Only allow scopes that refer to resource servers (e.g. offline_access is not allowed)
	// Check this by looking for '/' in the scope name
	for _, scope := range scopes {
		if !strings.Contains(scope, "/") {
			return fmt.Errorf("invalid scope name %s: must refer to a resource server", scope)
		}
	}

	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	for _, scope := range scopes {
		id, err := uuid.NewV7()
		if err != nil {
			return fmt.Errorf("failed to generate permission ID: %w", err)
		}

		var scopeID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT id FROM tbl_scope WHERE name = $1`, scope).Scan(&scopeID); err != nil {
			if errors.Is(err, database.ErrNoRows) {
				return ErrScopeNotFound
			}

			return fmt.Errorf("failed to get scope ID for scope %s: %w", scope, err)
		}

		if _, err := tx.Exec(ctx, `INSERT INTO tbl_permission (id, account_id, scope_id) VALUES ($1, $2, $3) ON CONFLICT (account_id, scope_id) DO NOTHING`, id, clientID, scopeID); err != nil {
			return fmt.Errorf("failed to assign scope %s to client %s: %w", scope, clientID, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (s *Service) AssignScopesToUser(ctx context.Context, userID uuid.UUID, scopes []string) error {
	// Users are also accounts, so we can reuse the client method
	return s.AssignScopesToClient(ctx, userID, scopes)
}

func (s *Service) GetScopesByAccountID(ctx context.Context, accountID uuid.UUID) ([]string, error) {
	query := `
		SELECT s.name
		FROM tbl_scope s
		JOIN tbl_permission p ON s.id = p.scope_id
		WHERE p.account_id = $1
	`

	rows, err := s.DB.Query(ctx, query, accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to query scopes for account %s: %w", accountID, err)
	}
	defer rows.Close()

	var scopes []string
	for rows.Next() {
		var scopeName string
		if err := rows.Scan(&scopeName); err != nil {
			return nil, fmt.Errorf("failed to scan scope name: %w", err)
		}
		scopes = append(scopes, scopeName)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over scope rows: %w", err)
	}

	return scopes, nil
}

func (s *Service) GetScopesByNames(ctx context.Context, scopes []string) (map[string]string, error) {
	if len(scopes) == 0 {
		return make(map[string]string), nil
	}

	query := `
		SELECT s.name, s.description
		FROM tbl_scope s
		WHERE s.name = ANY($1)
	`
	rows, err := s.DB.Query(ctx, query, scopes)
	if err != nil {
		return nil, fmt.Errorf("failed to query scopes by names: %w", err)
	}
	defer rows.Close()

	var foundScopes = make(map[string]string)
	for rows.Next() {
		var scopeName string
		var scopeDescription string
		if err := rows.Scan(&scopeName, &scopeDescription); err != nil {
			return nil, fmt.Errorf("failed to scan scope name: %w", err)
		}
		foundScopes[scopeName] = scopeDescription
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over scope rows: %w", err)
	}

	return foundScopes, nil
}

func (s *Service) GrantScopes(ctx context.Context, userID, clientID uuid.UUID, scopes []string) error {
	// Fetch scopes the user has permission for
	rows, err := s.DB.Query(ctx, `
		SELECT s.id 
		FROM tbl_scope s
		JOIN tbl_permission p ON s.id = p.scope_id
		WHERE p.account_id = $1 AND s.name = ANY($2)
	`, userID, scopes)
	if err != nil {
		return fmt.Errorf("failed to query existing granted scopes: %w", err)
	}
	defer rows.Close()

	var allowedScopeIDs []uuid.UUID
	for rows.Next() {
		var scopeID uuid.UUID
		if err := rows.Scan(&scopeID); err != nil {
			return fmt.Errorf("failed to scan scope ID: %w", err)
		}
		allowedScopeIDs = append(allowedScopeIDs, scopeID)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating over granted scope rows: %w", err)
	}

	// Grant scopes to account
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	for _, scopeID := range allowedScopeIDs {
		if _, err := tx.Exec(ctx, `INSERT INTO tbl_granted_scope (user_id, client_id, scope_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, userID, clientID, scopeID); err != nil {
			return fmt.Errorf("failed to grant scope %s to user %s: %w", scopeID, userID, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (s *Service) GetGrantedScopes(ctx context.Context, userID, clientID uuid.UUID) ([]string, error) {
	query := `
		SELECT s.name
		FROM tbl_scope s
		JOIN tbl_granted_scope gs ON s.id = gs.scope_id
		WHERE gs.user_id = $1 AND gs.client_id = $2
	`

	rows, err := s.DB.Query(ctx, query, userID, clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to query granted scopes: %w", err)
	}
	defer rows.Close()

	var grantedScopes []string
	for rows.Next() {
		var scope string
		if err := rows.Scan(&scope); err != nil {
			return nil, fmt.Errorf("failed to scan granted scope: %w", err)
		}
		grantedScopes = append(grantedScopes, scope)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over granted scope rows: %w", err)
	}

	return grantedScopes, nil
}

func (s *Service) GetUngrantedScopes(ctx context.Context, userID, clientID uuid.UUID, requestedScopes []string) ([]string, error) {
	if len(requestedScopes) == 0 {
		return []string{}, nil
	}

	// Get already granted scopes
	grantedScopes, err := s.GetGrantedScopes(ctx, userID, clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to get granted scopes: %w", err)
	}

	// Create a set of granted scopes for efficient lookup
	grantedSet := make(map[string]struct{})
	for _, scope := range grantedScopes {
		grantedSet[scope] = struct{}{}
	}

	// Find ungranted scopes
	var ungrantedScopes []string
	for _, requestedScope := range requestedScopes {
		if _, granted := grantedSet[requestedScope]; !granted {
			ungrantedScopes = append(ungrantedScopes, requestedScope)
		}
	}

	return ungrantedScopes, nil
}

func (s *Service) NewAuthorizationCode(clientID, userID uuid.UUID, scopes []string, redirectURI, codeChallenge, codeChallengeMethod string) (domain.AuthorizationCode, error) {
	// Generate authorization code
	code, err := util.GenerateRandomString(32)
	if err != nil {
		return domain.AuthorizationCode{}, fmt.Errorf("failed to generate authorization code: %w", err)
	}

	return domain.AuthorizationCode{
		Code:                code,
		ClientID:            clientID,
		UserID:              userID,
		Scopes:              scopes,
		RedirectURI:         redirectURI,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ExpiresAt:           time.Now().Add(10 * time.Minute).UTC(), // 10 minute expiry
	}, nil
}

func (s *Service) CreateAuthorizationCode(ctx context.Context, authCode domain.AuthorizationCode) (domain.AuthorizationCode, error) {
	query := `
		INSERT INTO tbl_authorization_code (
			code, client_id, user_id, scopes, redirect_uri, 
			code_challenge, code_challenge_method, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, created_at
	`

	err := s.DB.QueryRow(ctx, query,
		authCode.Code,
		authCode.ClientID,
		authCode.UserID,
		authCode.Scopes,
		authCode.RedirectURI,
		authCode.CodeChallenge,
		authCode.CodeChallengeMethod,
		authCode.ExpiresAt,
	).Scan(&authCode.ID, &authCode.CreatedAt)

	if err != nil {
		return domain.AuthorizationCode{}, fmt.Errorf("failed to save authorization code: %w", err)
	}

	return authCode, nil
}

func (s *Service) GetAuthorizationCodeByCode(ctx context.Context, code string) (domain.AuthorizationCode, error) {
	var authCode domain.AuthorizationCode

	query := `
		SELECT id, code, client_id, user_id, scopes, redirect_uri, 
		       code_challenge, code_challenge_method, expires_at, created_at
		FROM tbl_authorization_code 
		WHERE code = $1 AND expires_at > NOW()
	`

	err := s.DB.QueryRow(ctx, query, code).Scan(
		&authCode.ID,
		&authCode.Code,
		&authCode.ClientID,
		&authCode.UserID,
		&authCode.Scopes,
		&authCode.RedirectURI,
		&authCode.CodeChallenge,
		&authCode.CodeChallengeMethod,
		&authCode.ExpiresAt,
		&authCode.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, database.ErrNoRows) {
			return domain.AuthorizationCode{}, errors.New("authorization code not found or expired")
		}
		return domain.AuthorizationCode{}, fmt.Errorf("failed to get authorization code: %w", err)
	}

	return authCode, nil
}

func (s *Service) DeleteAuthorizationCode(ctx context.Context, code string) error {
	_, err := s.DB.Exec(ctx, "DELETE FROM tbl_authorization_code WHERE code = $1", code)
	if err != nil {
		return fmt.Errorf("failed to delete authorization code: %w", err)
	}
	return nil
}

func (s *Service) GetUserPermittedScopes(ctx context.Context, userID uuid.UUID, requestedScopes []string) ([]string, error) {
	if len(requestedScopes) == 0 {
		return []string{}, nil
	}

	query := `
		SELECT s.name
		FROM tbl_scope s
		JOIN tbl_permission p ON s.id = p.scope_id
		WHERE p.account_id = $1 AND s.name = ANY($2)
	`

	rows, err := s.DB.Query(ctx, query, userID, requestedScopes)
	if err != nil {
		return nil, fmt.Errorf("failed to query user permissions: %w", err)
	}
	defer rows.Close()

	var permittedScopes []string
	for rows.Next() {
		var scopeName string
		if err := rows.Scan(&scopeName); err != nil {
			return nil, fmt.Errorf("failed to scan scope name: %w", err)
		}
		permittedScopes = append(permittedScopes, scopeName)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating scope rows: %w", err)
	}

	return permittedScopes, nil
}

func (s *Service) NewAuthorizationRequest(clientID uuid.UUID, redirectURI, responseType string, scopes []string, state, codeChallenge, codeChallengeMethod, originalURL string) (*AuthorizationRequest, error) {
	// Validate PKCE parameters
	if err := ValidateCodeChallenge(codeChallenge, codeChallengeMethod); err != nil {
		return nil, fmt.Errorf("invalid PKCE parameters: %w", err)
	}

	return &AuthorizationRequest{
		ClientID:            clientID,
		Scopes:              scopes,
		RedirectURI:         redirectURI,
		State:               state,
		ResponseType:        responseType,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		OriginalURL:         originalURL,
	}, nil
}

// Refresh Token Methods

func (s *Service) NewRefreshToken(clientID, userID uuid.UUID, scopes []string) (domain.RefreshToken, error) {
	return s.RefreshTokenService.NewRefreshToken(clientID, userID, scopes)
}

func (s *Service) NewRefreshTokenFromParent(parentToken domain.RefreshToken, scopes []string) (domain.RefreshToken, error) {
	return s.RefreshTokenService.NewRefreshTokenFromParent(parentToken, scopes)
}

func (s *Service) CreateRefreshToken(ctx context.Context, refreshToken domain.RefreshToken) (domain.RefreshToken, error) {
	return s.RefreshTokenService.CreateRefreshToken(ctx, refreshToken)
}

func (s *Service) GetRefreshTokenByToken(ctx context.Context, token string) (domain.RefreshToken, error) {
	return s.RefreshTokenService.GetRefreshTokenByToken(ctx, token)
}

func (s *Service) MarkRefreshTokenAsUsed(ctx context.Context, token string) (domain.RefreshToken, error) {
	return s.RefreshTokenService.MarkRefreshTokenAsUsed(ctx, token)
}

func (s *Service) RevokeRefreshTokenChain(ctx context.Context, chainID uuid.UUID) error {
	return s.RefreshTokenService.RevokeRefreshTokenChain(ctx, chainID)
}

func (s *Service) CheckRefreshTokenReplay(ctx context.Context, token string) (bool, domain.RefreshToken, error) {
	return s.RefreshTokenService.CheckRefreshTokenReplay(ctx, token)
}

func (s *Service) DeleteRefreshToken(ctx context.Context, token string) error {
	return s.RefreshTokenService.DeleteRefreshToken(ctx, token)
}

// GenerateIDToken creates an OpenID Connect ID token for the user
func (s *Service) GenerateIDToken(ctx context.Context, user account.User, client account.Client, scopes []string, nonce string, signingKey *jwt.KeySet, issuer string) (string, error) {
	// Check if openid scope is present (required for ID tokens)
	if !slices.Contains(scopes, "openid") {
		return "", nil // No ID token if openid scope not requested
	}

	now := time.Now()

	// Build JWT using the helper pattern from your JWT package
	builder := helpers.NewBuilder()

	// Standard OpenID Connect claims
	builder.SetIssuer(issuer).
		SetSubject(user.ID.String()).
		SetAudience(client.PublicID).
		SetExpiresAt(now.Add(1 * time.Hour).Unix()).
		SetIssuedAt(now.Unix()).
		SetJTI(uuid.New().String())

	// Add nonce if provided (prevents replay attacks)
	if nonce != "" {
		builder.SetCustomClaim("nonce", nonce)
	}

	// Add auth_time (time when authentication occurred)
	builder.SetCustomClaim("auth_time", now.Unix())

	// Add email claim if email scope is requested
	if slices.Contains(scopes, "email") {
		builder.SetCustomClaim("email", user.Email).
			SetCustomClaim("email_verified", true)
	}

	// Add profile claims if profile scope is requested
	if slices.Contains(scopes, "profile") {
		// You can add more profile claims as needed based on your User model
		builder.SetCustomClaim("preferred_username", user.Email)
	}

	// Build and sign the token
	token := builder.Build()
	signedToken, err := jwt.Sign(token, signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign ID token: %w", err)
	}

	return signedToken, nil
}

func (s *Service) RevokeRefreshToken(ctx context.Context, token string) error {
	return s.RefreshTokenService.RevokeRefreshToken(ctx, token)
}

// RevokeAccessToken revokes a single access token by token value
func (s *Service) RevokeAccessToken(ctx context.Context, token string) error {
	_, err := s.DB.Exec(ctx, `
		UPDATE tbl_access_token 
		SET is_revoked = TRUE, used_at = NOW()
		WHERE token = $1 AND is_revoked = FALSE
	`, token)
	if err != nil {
		return fmt.Errorf("failed to revoke access token: %w", err)
	}
	return nil
}
