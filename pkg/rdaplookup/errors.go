package rdaplookup

import (
	"errors"
	"fmt"
	"net/http"
)

// Common error codes returned by the API.
const (
	ErrCodeNotFound       = "NOT_FOUND"
	ErrCodeInvalidRequest = "INVALID_REQUEST"
	ErrCodeUpstreamError  = "UPSTREAM_ERROR"
	ErrCodeRateLimited    = "RATE_LIMITED"
	ErrCodeInternalError  = "INTERNAL_ERROR"
)

// Common errors.
var (
	// ErrNotFound indicates the requested resource was not found.
	ErrNotFound = errors.New("resource not found")

	// ErrInvalidRequest indicates an invalid request.
	ErrInvalidRequest = errors.New("invalid request")

	// ErrRateLimited indicates the client has been rate limited.
	ErrRateLimited = errors.New("rate limited")

	// ErrTimeout indicates a request timeout.
	ErrTimeout = errors.New("request timeout")
)

// APIError represents an error response from the API.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("API error %d (%s): %s", e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("API error %d: %s", e.StatusCode, e.Message)
}

// IsNotFound returns true if the error indicates a not found response.
func (e *APIError) IsNotFound() bool {
	return e.StatusCode == http.StatusNotFound || e.Code == ErrCodeNotFound
}

// IsRateLimited returns true if the error indicates rate limiting.
func (e *APIError) IsRateLimited() bool {
	return e.StatusCode == http.StatusTooManyRequests || e.Code == ErrCodeRateLimited
}

// IsServerError returns true if the error is a server-side error.
func (e *APIError) IsServerError() bool {
	return e.StatusCode >= 500
}

// IsNotFoundError checks if an error is a not found error.
func IsNotFoundError(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.IsNotFound()
	}
	return errors.Is(err, ErrNotFound)
}

// IsRateLimitedError checks if an error is a rate limit error.
func IsRateLimitedError(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.IsRateLimited()
	}
	return errors.Is(err, ErrRateLimited)
}

// IsServerErrorFunc checks if an error is a server error.
func IsServerErrorFunc(err error) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.IsServerError()
	}
	return false
}
