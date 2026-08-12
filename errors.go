package godevauth

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/go-dev-auth/go-dev-auth/crypto"
	"github.com/go-dev-auth/go-dev-auth/storage"
)

// APIError is an error with an HTTP status and a stable machine readable
// code, rendered as {"message": ..., "code": ...} in responses.
type APIError struct {
	Status  int    `json:"-"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message"`
}

// Error implements the error interface.
func (e *APIError) Error() string {
	return fmt.Sprintf("%d %s: %s", e.Status, e.Code, e.Message)
}

// NewAPIError builds an APIError.
func NewAPIError(status int, code, message string) *APIError {
	return &APIError{Status: status, Code: code, Message: message}
}

// AsAPIError extracts an *APIError from err, wrapping unknown errors as
// internal server errors.
func AsAPIError(err error) *APIError {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr
	}
	if errors.Is(err, crypto.ErrHasherBusy) {
		return ErrServiceBusy
	}
	// A lost race against a unique index is a client-visible conflict,
	// not a server fault.
	if isUniqueViolation(err) {
		return NewAPIError(http.StatusConflict, "ALREADY_EXISTS", "Resource already exists")
	}
	return &APIError{Status: http.StatusInternalServerError, Code: "INTERNAL_SERVER_ERROR", Message: "internal server error"}
}

// isUniqueViolation reports whether err is a unique-constraint failure
// reported by the storage adapter.
func isUniqueViolation(err error) bool {
	return errors.Is(err, storage.ErrUniqueViolation)
}

// Common error constructors mirroring better-auth error codes.
var (
	ErrUserNotFound = NewAPIError(http.StatusBadRequest,
		"USER_NOT_FOUND", "User not found")
	ErrUserAlreadyExists = NewAPIError(http.StatusUnprocessableEntity,
		"USER_ALREADY_EXISTS", "User already exists")
	ErrInvalidEmailOrPassword = NewAPIError(http.StatusUnauthorized,
		"INVALID_EMAIL_OR_PASSWORD", "Invalid email or password")
	ErrInvalidPassword = NewAPIError(http.StatusBadRequest,
		"INVALID_PASSWORD", "Invalid password")
	ErrInvalidEmail = NewAPIError(http.StatusBadRequest,
		"INVALID_EMAIL", "Invalid email")
	ErrEmailNotVerified = NewAPIError(http.StatusForbidden,
		"EMAIL_NOT_VERIFIED", "Email not verified")
	ErrPasswordTooShort = NewAPIError(http.StatusBadRequest,
		"PASSWORD_TOO_SHORT", "Password too short")
	ErrPasswordTooLong = NewAPIError(http.StatusBadRequest,
		"PASSWORD_TOO_LONG", "Password too long")
	ErrUnauthorized = NewAPIError(http.StatusUnauthorized,
		"UNAUTHORIZED", "Unauthorized")
	ErrForbidden = NewAPIError(http.StatusForbidden,
		"FORBIDDEN", "Forbidden")
	ErrSessionExpired = NewAPIError(http.StatusUnauthorized,
		"SESSION_EXPIRED", "Session expired. Re-authenticate to perform this action.")
	// ErrSessionNotFresh is returned when a valid session is too old for
	// an operation that changes how the account is accessed (adding a
	// first password, for one). It is deliberately not a 401: the
	// session is genuine and must stay usable, so a client's blanket
	// "401 means sign out" handler would draw the wrong conclusion. The
	// correct client response is to re-authenticate the user and retry,
	// which is what the distinct code is for.
	ErrSessionNotFresh = NewAPIError(http.StatusForbidden,
		"SESSION_NOT_FRESH", "This action requires a recently authenticated session. Sign in again and retry.")
	ErrInvalidToken = NewAPIError(http.StatusBadRequest,
		"INVALID_TOKEN", "Invalid token")
	ErrProviderNotFound = NewAPIError(http.StatusNotFound,
		"PROVIDER_NOT_FOUND", "Provider not found")
	ErrAccountNotFound = NewAPIError(http.StatusBadRequest,
		"ACCOUNT_NOT_FOUND", "Account not found")
	ErrCredentialAccountNotFound = NewAPIError(http.StatusBadRequest,
		"CREDENTIAL_ACCOUNT_NOT_FOUND", "Credential account not found")
	ErrEmailCannotBeUpdated = NewAPIError(http.StatusBadRequest,
		"EMAIL_CAN_NOT_BE_UPDATED", "Email can not be updated")
	ErrSignUpDisabled = NewAPIError(http.StatusForbidden,
		"SIGNUP_DISABLED", "Sign up is disabled")
	ErrRateLimited = NewAPIError(http.StatusTooManyRequests,
		"RATE_LIMITED", "Too many requests. Please try again later.")
	ErrInvalidOrigin = NewAPIError(http.StatusForbidden,
		"INVALID_ORIGIN", "Invalid origin")
	ErrFailedToUnlinkLastAccount = NewAPIError(http.StatusBadRequest,
		"FAILED_TO_UNLINK_LAST_ACCOUNT", "You can't unlink your last account")
	ErrEmailVerificationDisabled = NewAPIError(http.StatusBadRequest,
		"VERIFICATION_DISABLED", "Email verification is not enabled")
	ErrInvalidBody = NewAPIError(http.StatusBadRequest,
		"INVALID_BODY", "Invalid request body")
	// ErrTokenDecryptionFailed is returned when a value stored
	// encrypted cannot be read with any configured secret — almost
	// always a rotated Config.Secret with no matching entry in
	// Config.PreviousSecrets. It is a 500 because it is a server
	// configuration fault, and it is an error rather than a fallback
	// because the alternative is forwarding ciphertext to a third
	// party.
	ErrTokenDecryptionFailed = NewAPIError(http.StatusInternalServerError,
		"TOKEN_DECRYPTION_FAILED", "A stored credential could not be decrypted")
	// ErrServiceBusy is returned when password hashing is saturated.
	// Shedding load with a retryable status is better than queueing
	// behind a multi-second backlog the client will time out on anyway.
	ErrServiceBusy = NewAPIError(http.StatusServiceUnavailable,
		"SERVICE_BUSY", "The service is busy. Please retry shortly.")
)
