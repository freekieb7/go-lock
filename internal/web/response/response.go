package response

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	apperrors "github.com/freekieb7/go-lock/internal/errors"
)

type APIResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message,omitempty"`
	Status  string `json:"status,omitempty"`
	Data    any    `json:"data,omitempty"`
}

func Redirect(w http.ResponseWriter, status int, url string) {
	w.Header().Set("Location", url)
	w.WriteHeader(status)
}

func JSONResponse(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload)
}

// ErrorResponse handles structured error responses
func ErrorResponse(w http.ResponseWriter, err error, logger *slog.Logger) {
	var appErr *apperrors.AppError

	if apperrors.IsType(err, apperrors.CodeInternalError) || !errors.As(err, &appErr) {
		// Log internal errors for debugging but don't expose details
		if logger != nil {
			logger.Error("Internal server error", slog.String("error", err.Error()))
		}

		appErr = apperrors.InternalError("An internal error occurred", err)
	} else if logger != nil {
		// Log structured application errors with context
		logger.Warn("Application error occurred",
			slog.String("code", appErr.Code),
			slog.String("message", appErr.Message),
			slog.String("cause", appErr.Error()))
	}

	JSONResponse(w, appErr.HTTPCode, APIResponse{
		Code:    appErr.HTTPCode,
		Status:  "error",
		Message: appErr.Message,
		Data: map[string]string{
			"error_code": appErr.Code,
		},
	})
}

// SuccessResponse handles successful API responses
func SuccessResponse(w http.ResponseWriter, data any) {
	JSONResponse(w, http.StatusOK, APIResponse{
		Code:   http.StatusOK,
		Status: "success",
		Data:   data,
	})
}

// ValidationErrorResponse handles validation error responses
func ValidationErrorResponse(w http.ResponseWriter, message string, details map[string]string, logger *slog.Logger) {
	if logger != nil {
		logger.Warn("Validation error",
			slog.String("message", message),
			slog.Any("details", details))
	}

	JSONResponse(w, http.StatusBadRequest, APIResponse{
		Code:    http.StatusBadRequest,
		Status:  "error",
		Message: message,
		Data: map[string]any{
			"error_code": apperrors.CodeValidationFailed,
			"details":    details,
		},
	})
}
