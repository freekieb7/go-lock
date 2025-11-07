package account

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/freekieb7/go-lock/internal/database"
	apperrors "github.com/freekieb7/go-lock/internal/errors"
	"github.com/freekieb7/go-lock/internal/util"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	// Deprecated: Use apperrors.NotFoundError instead
	ErrClientNotFound     = apperrors.NotFoundError("client not found", nil)
	ErrUserNotFound       = apperrors.NotFoundError("user not found", nil)
	ErrInvalidCredentials = apperrors.UnauthorizedError("invalid credentials", nil)
)

type Service struct {
	DB *database.Database
}

func NewService(db *database.Database) Service {
	return Service{
		DB: db,
	}
}

func (s *Service) NewClient(name, description string, redirectURIs []string, isConfidential bool, logoURI string) (Client, error) {
	// Validate inputs
	if name == "" {
		return Client{}, apperrors.ValidationError("client name cannot be empty", nil)
	}

	if redirectURIs == nil {
		redirectURIs = []string{}
	}

	publicID, err := util.GenerateRandomString(32)
	if err != nil {
		return Client{}, apperrors.InternalError("failed to generate client public ID", err)
	}

	secret, err := util.GenerateRandomString(32)
	if err != nil {
		return Client{}, apperrors.InternalError("failed to generate client secret", err)
	}

	return Client{
		PublicID:       publicID,
		Secret:         secret,
		Name:           name,
		Description:    description,
		RedirectURIs:   redirectURIs,
		IsConfidential: isConfidential,
		LogoURI:        logoURI,
	}, nil
}

func (s *Service) GetClientByID(ctx context.Context, clientID uuid.UUID) (Client, error) {
	var client Client

	query := `SELECT id, public_id, secret, name, description, redirect_uris, is_confidential, logo_uri, created_at FROM tbl_client WHERE id = $1`
	row := s.DB.QueryRow(ctx, query, clientID)
	if err := row.Scan(&client.ID, &client.PublicID, &client.Secret, &client.Name, &client.Description, &client.RedirectURIs, &client.IsConfidential, &client.LogoURI, &client.CreatedAt); err != nil {
		if err == database.ErrNoRows {
			return Client{}, ErrClientNotFound
		}
		return Client{}, fmt.Errorf("failed to get client by ID: %w", err)
	}

	return client, nil
}

func (s *Service) GetClientByPublicID(ctx context.Context, publicID string) (Client, error) {
	var client Client

	query := `SELECT id, public_id, secret, name, description, redirect_uris, is_confidential, logo_uri, created_at FROM tbl_client WHERE public_id = $1`
	row := s.DB.QueryRow(ctx, query, publicID)
	if err := row.Scan(&client.ID, &client.PublicID, &client.Secret, &client.Name, &client.Description, &client.RedirectURIs, &client.IsConfidential, &client.LogoURI, &client.CreatedAt); err != nil {
		if err == database.ErrNoRows {
			return Client{}, ErrClientNotFound
		}
		return Client{}, fmt.Errorf("failed to get client by public ID: %w", err)
	}

	return client, nil
}

func (s *Service) CreateClient(ctx context.Context, client Client) (Client, error) {
	// Insert the new client into the database
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return Client{}, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	if err := tx.QueryRow(ctx, `INSERT INTO tbl_account (type) VALUES ('client') RETURNING id, created_at`).Scan(&client.ID, &client.CreatedAt); err != nil {
		return Client{}, fmt.Errorf("failed to save account: %w", err)
	}

	if _, err := tx.Exec(ctx, `INSERT INTO tbl_client (id, public_id, secret, name, description, redirect_uris, is_confidential, logo_uri) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, client.ID, client.PublicID, client.Secret, client.Name, client.Description, client.RedirectURIs, client.IsConfidential, client.LogoURI); err != nil {
		return Client{}, fmt.Errorf("failed to save client: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return Client{}, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return client, nil
}

func (s *Service) UpdateClient(ctx context.Context, client Client) (Client, error) {
	_, err := s.DB.Exec(ctx, `UPDATE tbl_client SET name = $1, description = $2, redirect_uris = $3, is_confidential = $4, logo_uri = $5 WHERE id = $6`, client.Name, client.Description, client.RedirectURIs, client.IsConfidential, client.LogoURI, client.ID)
	if err != nil {
		return Client{}, fmt.Errorf("failed to update client: %w", err)
	}

	return client, nil
}

func (s *Service) DeleteClientByID(ctx context.Context, clientID uuid.UUID) error {
	_, err := s.DB.Exec(ctx, `DELETE FROM tbl_account WHERE id = $1`, clientID)
	if err != nil {
		return fmt.Errorf("failed to delete client: %w", err)
	}
	return nil
}

type ListClientsParams struct {
	PageSize int
	Token    string
}

type ListClientsResult struct {
	Clients   []Client
	NextToken string
	PrevToken string
}

type ListClientsCursor struct {
	CreatedAt time.Time `json:"created_at"`
	ID        uuid.UUID `json:"id"`
	Direction string    `json:"direction"`
}

func (s *Service) ListClients(ctx context.Context, params ListClientsParams) (ListClientsResult, error) {
	// Set default page size if invalid
	if params.PageSize <= 0 {
		return ListClientsResult{}, fmt.Errorf("page size must be greater than zero")
	}

	cursor, err := decodeListClientsCursor(params.Token)
	if err != nil {
		return ListClientsResult{}, fmt.Errorf("invalid pagination token: %w", err)
	}

	// Extract direction from cursor, default to "next" for first page
	direction := "next"
	if cursor.Direction != "" {
		direction = cursor.Direction
	}

	query := `SELECT id, public_id, secret, name, description, redirect_uris, is_confidential, logo_uri, created_at FROM tbl_client `
	args := []any{}
	argIdx := 1

	order := "DESC"
	cmp := "<"

	if direction == "prev" {
		order = "ASC"
		cmp = ">"
	}

	if cursor.ID != uuid.Nil {
		query += fmt.Sprintf("WHERE (created_at, id) %s ($%d, $%d) ", cmp, argIdx, argIdx+1)
		args = append(args, cursor.CreatedAt, cursor.ID)
		argIdx += 2
	}

	query += fmt.Sprintf("ORDER BY created_at %s, id %s ", order, order)
	query += fmt.Sprintf("LIMIT $%d", argIdx)
	args = append(args, params.PageSize+1) // Fetch one extra to detect more pages

	rows, err := s.DB.Query(ctx, query, args...)
	if err != nil {
		return ListClientsResult{}, fmt.Errorf("failed to query clients: %w", err)
	}
	defer rows.Close()

	clients := []Client{}
	for rows.Next() {
		var client Client
		if err := rows.Scan(&client.ID, &client.PublicID, &client.Secret, &client.Name, &client.Description, &client.RedirectURIs, &client.IsConfidential, &client.LogoURI, &client.CreatedAt); err != nil {
			return ListClientsResult{}, fmt.Errorf("failed to scan client: %w", err)
		}
		clients = append(clients, client)
	}

	if len(clients) == 0 {
		return ListClientsResult{
			Clients: clients,
		}, nil
	}

	if len(clients) == 0 {
		return ListClientsResult{
			Clients: clients,
		}, nil
	}

	// Check if we have more results than requested (indicates more pages)
	hasMore := len(clients) > params.PageSize
	if hasMore {
		clients = clients[:params.PageSize] // Remove the extra record
	}

	// If fetching previous page, reverse results to maintain order
	if direction == "prev" {
		for i, j := 0, len(clients)-1; i < j; i, j = i+1, j-1 {
			clients[i], clients[j] = clients[j], clients[i]
		}
	}

	// Generate next/prev tokens based on actual data availability
	var nextCursor, prevCursor string

	if len(clients) > 0 {
		// Generate next token (for older records)
		showNext := (direction == "next" && hasMore) || (direction == "prev")
		if showNext {
			if nextCursorStr, err := encodeListClientsCursor(ListClientsCursor{
				ID:        clients[len(clients)-1].ID,
				CreatedAt: clients[len(clients)-1].CreatedAt,
				Direction: "next",
			}); err == nil {
				nextCursor = nextCursorStr
			}
		}

		// Generate prev token (for newer records)
		showPrev := (direction == "prev" && hasMore) || (direction == "next" && params.Token != "")
		if showPrev {
			if prevCursorStr, err := encodeListClientsCursor(ListClientsCursor{
				ID:        clients[0].ID,
				CreatedAt: clients[0].CreatedAt,
				Direction: "prev",
			}); err == nil {
				prevCursor = prevCursorStr
			}
		}
	}

	return ListClientsResult{
		Clients:   clients,
		NextToken: nextCursor,
		PrevToken: prevCursor,
	}, nil
}

func encodeListClientsCursor(cursor ListClientsCursor) (string, error) {
	data, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func decodeListClientsCursor(token string) (ListClientsCursor, error) {
	if token == "" {
		return ListClientsCursor{}, nil
	}
	data, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return ListClientsCursor{}, err
	}
	var cursor ListClientsCursor
	err = json.Unmarshal(data, &cursor)
	return cursor, err
}

func (s *Service) NewUser(email, password string) (User, error) {
	// Validate inputs
	if email == "" {
		return User{}, fmt.Errorf("user email cannot be empty")
	}
	if password == "" {
		return User{}, fmt.Errorf("user password cannot be empty")
	}

	// Hash password
	passwordHash, err := s.HashPassword(password)
	if err != nil {
		return User{}, fmt.Errorf("failed to hash password: %w", err)
	}

	return User{
		Type:         "user",
		Email:        email,
		PasswordHash: string(passwordHash),
	}, nil
}

func (s *Service) GetUserByID(ctx context.Context, userID uuid.UUID) (User, error) {
	query := `
		SELECT id, type, email, password_hash
		FROM tbl_user 
		WHERE id = $1
	`

	var user User
	err := s.DB.QueryRow(ctx, query, userID).Scan(
		&user.ID,
		&user.Type,
		&user.Email,
		&user.PasswordHash,
	)

	if err != nil {
		if errors.Is(err, database.ErrNoRows) {
			return User{}, ErrUserNotFound
		}
		return User{}, fmt.Errorf("failed to get user by ID: %w", err)
	}

	return user, nil
}

func (s *Service) CreateUser(ctx context.Context, user User) (User, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return User{}, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	if err := tx.QueryRow(ctx, `INSERT INTO tbl_account (type) VALUES ('user') RETURNING id, created_at`).Scan(&user.ID, &user.CreatedAt); err != nil {
		return User{}, fmt.Errorf("failed to save account: %w", err)
	}

	if _, err := tx.Exec(ctx, `INSERT INTO tbl_user (id, type, email, password_hash) VALUES ($1, $2, $3, $4)`, user.ID, user.Type, user.Email, user.PasswordHash); err != nil {
		return User{}, fmt.Errorf("failed to save user: %w", err)
	}

	// Assign default scopes to the new user
	if err := s.assignDefaultScopes(ctx, tx, user.ID); err != nil {
		return User{}, fmt.Errorf("failed to assign default scopes to user: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return User{}, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return user, nil
}

func (s *Service) UpdateUser(ctx context.Context, user User) (User, error) {
	_, err := s.DB.Exec(ctx, `UPDATE tbl_user SET type = $1, email = $2, password_hash = $3 WHERE id = $4`, user.Type, user.Email, user.PasswordHash, user.ID)
	if err != nil {
		return User{}, fmt.Errorf("failed to update user: %w", err)
	}
	return user, nil
}

func (s *Service) DeleteUserByID(ctx context.Context, userID uuid.UUID) error {
	_, err := s.DB.Exec(ctx, `DELETE FROM tbl_account WHERE id = $1`, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	return nil
}

type ListUsersParams struct {
	PageSize int
	Token    string
}

type ListUsersResult struct {
	Users     []User
	NextToken string
	PrevToken string
}

type ListUsersCursor struct {
	CreatedAt time.Time `json:"created_at"`
	ID        uuid.UUID `json:"id"`
	Direction string    `json:"direction"`
}

func (s *Service) ListUsers(ctx context.Context, params ListUsersParams) (ListUsersResult, error) {
	// Set default page size if invalid
	if params.PageSize <= 0 {
		return ListUsersResult{}, fmt.Errorf("page size must be greater than zero")
	}

	cursor, err := decodeListUsersCursor(params.Token)
	if err != nil {
		return ListUsersResult{}, fmt.Errorf("invalid pagination token: %w", err)
	}

	// Extract direction from cursor, default to "next" for first page
	direction := "next"
	if cursor.Direction != "" {
		direction = cursor.Direction
	}

	query := `SELECT id, type, email, created_at FROM tbl_user `
	args := []any{}
	argIdx := 1

	order := "DESC"
	cmp := "<"

	if direction == "prev" {
		order = "ASC"
		cmp = ">"
	}

	if cursor.ID != uuid.Nil {
		query += fmt.Sprintf("WHERE (created_at, id) %s ($%d, $%d) ", cmp, argIdx, argIdx+1)
		args = append(args, cursor.CreatedAt, cursor.ID)
		argIdx += 2
	}

	query += fmt.Sprintf("ORDER BY created_at %s, id %s ", order, order)
	query += fmt.Sprintf("LIMIT $%d", argIdx)
	args = append(args, params.PageSize+1) // Fetch one extra to detect more pages

	rows, err := s.DB.Query(ctx, query, args...)
	if err != nil {
		return ListUsersResult{}, fmt.Errorf("failed to query clients: %w", err)
	}
	defer rows.Close()

	users := make([]User, 0, params.PageSize+1)
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Type, &user.Email, &user.CreatedAt); err != nil {
			return ListUsersResult{}, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, user)
	}

	if len(users) == 0 {
		return ListUsersResult{
			Users: users,
		}, nil
	}

	if len(users) == 0 {
		return ListUsersResult{
			Users: users,
		}, nil
	}

	// Check if we have more results than requested (indicates more pages)
	hasMore := len(users) > params.PageSize
	if hasMore {
		users = users[:params.PageSize] // Remove the extra record
	}

	// If fetching previous page, reverse results to maintain order
	if direction == "prev" {
		for i, j := 0, len(users)-1; i < j; i, j = i+1, j-1 {
			users[i], users[j] = users[j], users[i]
		}
	}

	// Generate next/prev tokens based on actual data availability
	var nextCursor, prevCursor string

	if len(users) > 0 {
		// Generate next token (for older records)
		showNext := (direction == "next" && hasMore) || (direction == "prev")
		if showNext {
			if nextCursorStr, err := encodeListUsersCursor(ListUsersCursor{
				ID:        users[len(users)-1].ID,
				CreatedAt: users[len(users)-1].CreatedAt,
				Direction: "next",
			}); err == nil {
				nextCursor = nextCursorStr
			}
		}

		// Generate prev token (for newer records)
		showPrev := (direction == "prev" && hasMore) || (direction == "next" && params.Token != "")
		if showPrev {
			if prevCursorStr, err := encodeListUsersCursor(ListUsersCursor{
				ID:        users[0].ID,
				CreatedAt: users[0].CreatedAt,
				Direction: "prev",
			}); err == nil {
				prevCursor = prevCursorStr
			}
		}
	}

	return ListUsersResult{
		Users:     users,
		NextToken: nextCursor,
		PrevToken: prevCursor,
	}, nil
}

func encodeListUsersCursor(cursor ListUsersCursor) (string, error) {
	data, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func decodeListUsersCursor(token string) (ListUsersCursor, error) {
	if token == "" {
		return ListUsersCursor{}, nil
	}
	data, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return ListUsersCursor{}, err
	}
	var cursor ListUsersCursor
	err = json.Unmarshal(data, &cursor)
	return cursor, err
}

// assignDefaultScopes assigns default OAuth scopes to a newly created user
func (s *Service) assignDefaultScopes(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
	// Define default scopes that every user should have
	defaultScopes := []string{
		"offline_access", // Allows refresh tokens
		"openid",         // OpenID Connect identity
		"email",          // Email access
	}

	// Get scope IDs for the default scopes
	query := `SELECT id, name FROM tbl_scope WHERE name = ANY($1)`
	rows, err := tx.Query(ctx, query, defaultScopes)
	if err != nil {
		return fmt.Errorf("failed to query default scopes: %w", err)
	}
	defer rows.Close()

	var scopeIDs []uuid.UUID
	foundScopes := make(map[string]bool)

	for rows.Next() {
		var scopeID uuid.UUID
		var scopeName string
		if err := rows.Scan(&scopeID, &scopeName); err != nil {
			return fmt.Errorf("failed to scan scope: %w", err)
		}
		scopeIDs = append(scopeIDs, scopeID)
		foundScopes[scopeName] = true
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating over scope rows: %w", err)
	}

	// Check if all default scopes were found
	for _, scope := range defaultScopes {
		if !foundScopes[scope] {
			return fmt.Errorf("default scope '%s' not found in database", scope)
		}
	}

	// Insert permissions for the default scopes
	for _, scopeID := range scopeIDs {
		if _, err := tx.Exec(ctx, `
			INSERT INTO tbl_permission (account_id, scope_id) 
			VALUES ($1, $2) 
			ON CONFLICT (account_id, scope_id) DO NOTHING
		`, userID, scopeID); err != nil {
			return fmt.Errorf("failed to insert permission for scope %s: %w", scopeID, err)
		}
	}

	return nil
}

func (s *Service) AuthenticateUser(ctx context.Context, email, password string) (User, error) {
	var user User

	query := `SELECT id, type, email, password_hash FROM tbl_user WHERE email = $1`
	row := s.DB.QueryRow(ctx, query, email)
	if err := row.Scan(&user.ID, &user.Type, &user.Email, &user.PasswordHash); err != nil {
		if err == database.ErrNoRows {
			return User{}, ErrInvalidCredentials
		}
		return User{}, fmt.Errorf("failed to get user by email: %w", err)
	}

	// Verify password
	if err := s.CheckPasswordHash(password, user.PasswordHash); err != nil {
		return User{}, ErrInvalidCredentials
	}

	return user, nil
}

func (s *Service) HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hashedPassword), nil
}

func (s *Service) CheckPasswordHash(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
