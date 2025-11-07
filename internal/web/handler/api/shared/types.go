package shared

import (
	"time"
)

// Common API response types and constants

const (
	// Error messages
	ErrInternalServer             = "Internal server error"
	ErrInvalidRequestBody         = "Invalid request body"
	ErrInvalidJSONFormat          = "Invalid JSON format"
	ErrResourceNotFound           = "Resource not found"
	ErrInvalidIDFormat            = "Invalid ID format"
	ErrMissingIDInPath            = "Missing ID in URL path"
	ErrInvalidEmailFormat         = "Invalid email format"
	ErrInvalidPasswordLength      = "Password must be at least 8 characters long"
	ErrEmailRequired              = "Email is required"
	ErrPasswordRequired           = "Password is required"
	ErrNameRequired               = "Name is required"
	ErrRedirectURIRequired        = "At least one redirect URI is required"
	ErrValidRedirectURI           = "Redirect URIs must be valid URLs starting with http:// or https://"
	ErrAtLeastOneValidURI         = "At least one valid redirect URI is required"
	ErrInvalidUserType            = "User type must be 'user' or 'admin'"
	ErrEmailAlreadyExists         = "User with this email already exists"
	ErrClientNotFound             = "Client not found"
	ErrUserNotFound               = "User not found"
	ErrScopeNotFound              = "One or more scopes not found"
	ErrNoUpdatesProvided          = "No valid updates provided"
	ErrFailedPasswordUpdate       = "Failed to update password"
	ErrFailedUserUpdate           = "Failed to update user"
	ErrFailedUserRetrieve         = "Failed to retrieve user"
	ErrFailedUserDelete           = "Failed to delete user"
	ErrInvalidRequest             = "Invalid request"
	ErrResourceServerExists       = "Resource server already exists"
	ErrResourceServerURLRequired  = "Resource server URL is required"
	ErrResourceServerNotFound     = "Resource server not found"
	ErrFailedResourceServerUpdate = "Failed to update resource server"
	ErrFailedResourceServerDelete = "Failed to delete resource server"

	// Status codes
	StatusSuccess        = "SUCCESS"
	StatusError          = "ERROR"
	StatusInvalidRequest = "INVALID_REQUEST"
	StatusNotFound       = "NOT_FOUND"
	StatusConflict       = "CONFLICT"

	// Success messages
	MsgClientCreated           = "Client created successfully"
	MsgClientRetrieved         = "Client retrieved successfully"
	MsgClientUpdated           = "Client updated successfully"
	MsgClientDeleted           = "Client deleted successfully"
	MsgClientScopesRetrieved   = "Client scopes retrieved successfully"
	MsgUserCreated             = "User created successfully"
	MsgUserRetrieved           = "User retrieved successfully"
	MsgUserUpdated             = "User updated successfully"
	MsgUserDeleted             = "User deleted successfully"
	MsgUserScopesRetrieved     = "User scopes retrieved successfully"
	MsgResourceServerRetrieved = "Resource server retrieved successfully"
	MsgResourceServerUpdated   = "Resource server updated successfully"
)

// Client-related types
type ListClientsResponse struct {
	Clients       []ClientResponse `json:"clients"`
	PrevPageToken string           `json:"previous_page_token"`
	NextPageToken string           `json:"next_page_token"`
}

type ClientResponse struct {
	ID             string   `json:"id"`
	ClientID       string   `json:"client_id"`
	ClientSecret   string   `json:"client_secret,omitempty"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	RedirectURIs   []string `json:"redirect_uris"`
	IsConfidential bool     `json:"is_confidential"`
	LogoURI        string   `json:"logo_uri"`
}

type CreateClientRequest struct {
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	RedirectURIs   []string `json:"redirect_uris"`
	IsConfidential bool     `json:"is_confidential"`
	LogoURI        string   `json:"logo_uri"`
}

type UpdateClientRequest struct {
	Name           string   `json:"name,omitempty"`
	Description    string   `json:"description,omitempty"`
	RedirectURIs   []string `json:"redirect_uris,omitempty"`
	IsConfidential *bool    `json:"is_confidential,omitempty"` // Use pointer to detect if provided
	LogoURI        string   `json:"logo_uri,omitempty"`
}

type CreateClientPermissionRequest struct {
	Scopes []string `json:"scopes"`
}

type ClientPermissionsResponse struct {
	Scopes []string `json:"scopes"`
}

// User-related types
type ListUsersResponse struct {
	Users         []UserResponse `json:"users"`
	PrevPageToken string         `json:"previous_page_token"`
	NextPageToken string         `json:"next_page_token"`
}

type CreateUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Type     string `json:"type,omitempty"` // optional: "user" or "admin", defaults to "user"
}

type UserResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Type  string `json:"type"`
}

type UpdateUserRequest struct {
	Email    string `json:"email,omitempty"`
	Password string `json:"password,omitempty"`
	Type     string `json:"type,omitempty"`
}

type AddUserPermissionsRequest struct {
	Scopes []string `json:"scopes"`
}

type UserPermissionsResponse struct {
	Scopes []string `json:"scopes"`
}

// Resource Server-related types
type ListResourceServersResponse struct {
	ResourceServers []ResourceServerResponse `json:"resource_servers"`
	PrevPageToken   string                   `json:"previous_page_token"`
	NextPageToken   string                   `json:"next_page_token"`
}

type CreateResourceServerRequest struct {
	URL         string                             `json:"url"`
	Description string                             `json:"description"`
	Scopes      []CreateResourceServerScopeRequest `json:"scopes"`
}

type CreateResourceServerScopeRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type ResourceServerResponse struct {
	ID          string                        `json:"id"`
	URL         string                        `json:"url"`
	Description string                        `json:"description"`
	Scopes      []ResourceServerScopeResponse `json:"scopes"`
	CreatedAt   time.Time                     `json:"created_at"`
}

type UpdateResourceServerRequest struct {
	Description string `json:"description,omitempty"`
}

type ResourceServerScopeResponse struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}
