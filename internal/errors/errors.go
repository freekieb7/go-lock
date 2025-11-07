package errors

import (
	"errors"
	"fmt"
	"net/http"
)

// AppError represents a structured application error with context
type AppError struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	Details  string `json:"details,omitempty"`
	HTTPCode int    `json:"-"`
	Cause    error  `json:"-"`
}

func (e *AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (caused by: %v)", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *AppError) Unwrap() error {
	return e.Cause
}

// Common error codes
const (
	CodeValidationFailed = "VALIDATION_FAILED"
	CodeNotFound         = "NOT_FOUND"
	CodeUnauthorized     = "UNAUTHORIZED"
	CodeForbidden        = "FORBIDDEN"
	CodeInternalError    = "INTERNAL_ERROR"
	CodeDatabaseError    = "DATABASE_ERROR"
	CodeConfigError      = "CONFIG_ERROR"
	CodeOAuthError       = "OAUTH_ERROR"
	CodeRateLimited      = "RATE_LIMITED"
	CodeInvalidRequest   = "INVALID_REQUEST"

	// OAuth 2.0 specific error codes (RFC 6749)
	CodeInvalidClient           = "invalid_client"
	CodeInvalidGrant            = "invalid_grant"
	CodeUnsupportedGrantType    = "unsupported_grant_type"
	CodeInvalidScope            = "invalid_scope"
	CodeAccessDenied            = "access_denied"
	CodeUnsupportedResponseType = "unsupported_response_type"

	// Cache-specific error codes
	CodeCacheError       = "CACHE_ERROR"
	CodeCacheTimeout     = "CACHE_TIMEOUT"
	CodeCacheUnavailable = "CACHE_UNAVAILABLE"

	// Session-specific error codes
	CodeSessionExpired  = "SESSION_EXPIRED"
	CodeSessionNotFound = "SESSION_NOT_FOUND"
	CodeSessionInvalid  = "SESSION_INVALID"
)

// Error constructors
func ValidationError(message string, cause error) *AppError {
	return &AppError{
		Code:     CodeValidationFailed,
		Message:  message,
		HTTPCode: http.StatusBadRequest,
		Cause:    cause,
	}
}

func NotFoundError(message string, cause error) *AppError {
	return &AppError{
		Code:     CodeNotFound,
		Message:  message,
		HTTPCode: http.StatusNotFound,
		Cause:    cause,
	}
}

func UnauthorizedError(message string, cause error) *AppError {
	return &AppError{
		Code:     CodeUnauthorized,
		Message:  message,
		HTTPCode: http.StatusUnauthorized,
		Cause:    cause,
	}
}

func ForbiddenError(message string, cause error) *AppError {
	return &AppError{
		Code:     CodeForbidden,
		Message:  message,
		HTTPCode: http.StatusForbidden,
		Cause:    cause,
	}
}

func InternalError(message string, cause error) *AppError {
	return &AppError{
		Code:     CodeInternalError,
		Message:  message,
		HTTPCode: http.StatusInternalServerError,
		Cause:    cause,
	}
}

func DatabaseError(message string, cause error) *AppError {
	return &AppError{
		Code:     CodeDatabaseError,
		Message:  message,
		HTTPCode: http.StatusInternalServerError,
		Cause:    cause,
	}
}

func ConfigError(message string, cause error) *AppError {
	return &AppError{
		Code:     CodeConfigError,
		Message:  message,
		HTTPCode: http.StatusInternalServerError,
		Cause:    cause,
	}
}

func OAuthError(message string, cause error) *AppError {
	return &AppError{
		Code:     CodeOAuthError,
		Message:  message,
		HTTPCode: http.StatusBadRequest,
		Cause:    cause,
	}
}

func RateLimitedError(message string, cause error) *AppError {
	return &AppError{
		Code:     CodeRateLimited,
		Message:  message,
		HTTPCode: http.StatusTooManyRequests,
		Cause:    cause,
	}
}

func InvalidRequestError(message string, cause error) *AppError {
	return &AppError{
		Code:     CodeInvalidRequest,
		Message:  message,
		HTTPCode: http.StatusBadRequest,
		Cause:    cause,
	}
}

// OAuth 2.0 specific error constructors
func InvalidClientError(message string, cause error) *AppError {
	return &AppError{
		Code:     CodeInvalidClient,
		Message:  message,
		HTTPCode: http.StatusUnauthorized,
		Cause:    cause,
	}
}

func InvalidGrantError(message string, cause error) *AppError {
	return &AppError{
		Code:     CodeInvalidGrant,
		Message:  message,
		HTTPCode: http.StatusBadRequest,
		Cause:    cause,
	}
}

func UnsupportedGrantTypeError(message string, cause error) *AppError {
	return &AppError{
		Code:     CodeUnsupportedGrantType,
		Message:  message,
		HTTPCode: http.StatusBadRequest,
		Cause:    cause,
	}
}

func InvalidScopeError(message string, cause error) *AppError {
	return &AppError{
		Code:     CodeInvalidScope,
		Message:  message,
		HTTPCode: http.StatusBadRequest,
		Cause:    cause,
	}
}

func AccessDeniedError(message string, cause error) *AppError {
	return &AppError{
		Code:     CodeAccessDenied,
		Message:  message,
		HTTPCode: http.StatusForbidden,
		Cause:    cause,
	}
}

func UnsupportedResponseTypeError(message string, cause error) *AppError {
	return &AppError{
		Code:     CodeUnsupportedResponseType,
		Message:  message,
		HTTPCode: http.StatusBadRequest,
		Cause:    cause,
	}
}

// Cache-specific error constructors
func CacheError(message string, cause error) *AppError {
	return &AppError{
		Code:     CodeCacheError,
		Message:  message,
		HTTPCode: http.StatusInternalServerError,
		Cause:    cause,
	}
}

func CacheTimeoutError(message string, cause error) *AppError {
	return &AppError{
		Code:     CodeCacheTimeout,
		Message:  message,
		HTTPCode: http.StatusInternalServerError,
		Cause:    cause,
	}
}

func CacheUnavailableError(message string, cause error) *AppError {
	return &AppError{
		Code:     CodeCacheUnavailable,
		Message:  message,
		HTTPCode: http.StatusServiceUnavailable,
		Cause:    cause,
	}
}

// Session-specific error constructors
func SessionExpiredError(message string, cause error) *AppError {
	return &AppError{
		Code:     CodeSessionExpired,
		Message:  message,
		HTTPCode: http.StatusUnauthorized,
		Cause:    cause,
	}
}

func SessionNotFoundError(message string, cause error) *AppError {
	return &AppError{
		Code:     CodeSessionNotFound,
		Message:  message,
		HTTPCode: http.StatusUnauthorized,
		Cause:    cause,
	}
}

func SessionInvalidError(message string, cause error) *AppError {
	return &AppError{
		Code:     CodeSessionInvalid,
		Message:  message,
		HTTPCode: http.StatusUnauthorized,
		Cause:    cause,
	}
}

// Wrap wraps an existing error with additional context
func Wrap(err error, code, message string) *AppError {
	if err == nil {
		return nil
	}

	// If it's already an AppError, preserve the original code but update message
	var appErr *AppError
	if errors.As(err, &appErr) {
		return &AppError{
			Code:     appErr.Code,
			Message:  fmt.Sprintf("%s: %s", message, appErr.Message),
			HTTPCode: appErr.HTTPCode,
			Cause:    appErr.Cause,
		}
	}

	// Determine HTTP code based on error code
	httpCode := http.StatusInternalServerError
	switch code {
	case CodeValidationFailed, CodeInvalidRequest, CodeOAuthError,
		CodeInvalidGrant, CodeInvalidScope, CodeUnsupportedGrantType, CodeUnsupportedResponseType:
		httpCode = http.StatusBadRequest
	case CodeNotFound, CodeSessionNotFound:
		httpCode = http.StatusNotFound
	case CodeUnauthorized, CodeInvalidClient, CodeSessionExpired, CodeSessionInvalid:
		httpCode = http.StatusUnauthorized
	case CodeForbidden, CodeAccessDenied:
		httpCode = http.StatusForbidden
	case CodeCacheUnavailable:
		httpCode = http.StatusServiceUnavailable
	case CodeRateLimited:
		httpCode = http.StatusTooManyRequests
	}

	return &AppError{
		Code:     code,
		Message:  message,
		HTTPCode: httpCode,
		Cause:    err,
	}
}

// IsType checks if an error is of a specific type/code
func IsType(err error, code string) bool {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Code == code
	}
	return false
}

// GetHTTPCode extracts the HTTP status code from an error
func GetHTTPCode(err error) int {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.HTTPCode
	}
	return http.StatusInternalServerError
}
