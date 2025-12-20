package rdaplookup

import (
	"errors"
	"testing"
)

func TestAPIError_Error(t *testing.T) {
	tests := []struct {
		name string
		err  *APIError
		want string
	}{
		{
			name: "with code",
			err: &APIError{
				StatusCode: 404,
				Code:       "NOT_FOUND",
				Message:    "Domain not found",
			},
			want: "API error 404 (NOT_FOUND): Domain not found",
		},
		{
			name: "without code",
			err: &APIError{
				StatusCode: 500,
				Message:    "Internal server error",
			},
			want: "API error 500: Internal server error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestAPIError_IsNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  *APIError
		want bool
	}{
		{
			name: "404 status code",
			err:  &APIError{StatusCode: 404},
			want: true,
		},
		{
			name: "NOT_FOUND code",
			err:  &APIError{StatusCode: 200, Code: "NOT_FOUND"},
			want: true,
		},
		{
			name: "not a 404",
			err:  &APIError{StatusCode: 500},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.IsNotFound(); got != tt.want {
				t.Errorf("IsNotFound() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAPIError_IsRateLimited(t *testing.T) {
	tests := []struct {
		name string
		err  *APIError
		want bool
	}{
		{
			name: "429 status code",
			err:  &APIError{StatusCode: 429},
			want: true,
		},
		{
			name: "RATE_LIMITED code",
			err:  &APIError{StatusCode: 200, Code: "RATE_LIMITED"},
			want: true,
		},
		{
			name: "not rate limited",
			err:  &APIError{StatusCode: 500},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.IsRateLimited(); got != tt.want {
				t.Errorf("IsRateLimited() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAPIError_IsServerError(t *testing.T) {
	tests := []struct {
		name string
		err  *APIError
		want bool
	}{
		{
			name: "500 error",
			err:  &APIError{StatusCode: 500},
			want: true,
		},
		{
			name: "502 error",
			err:  &APIError{StatusCode: 502},
			want: true,
		},
		{
			name: "400 error",
			err:  &APIError{StatusCode: 400},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.IsServerError(); got != tt.want {
				t.Errorf("IsServerError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsNotFoundError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "APIError not found",
			err:  &APIError{StatusCode: 404, Code: "NOT_FOUND"},
			want: true,
		},
		{
			name: "ErrNotFound sentinel",
			err:  ErrNotFound,
			want: true,
		},
		{
			name: "wrapped ErrNotFound",
			err:  errors.New("wrapped: " + ErrNotFound.Error()),
			want: false,
		},
		{
			name: "other error",
			err:  errors.New("something else"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsNotFoundError(tt.err); got != tt.want {
				t.Errorf("IsNotFoundError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsRateLimitedError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "APIError rate limited",
			err:  &APIError{StatusCode: 429, Code: "RATE_LIMITED"},
			want: true,
		},
		{
			name: "ErrRateLimited sentinel",
			err:  ErrRateLimited,
			want: true,
		},
		{
			name: "other error",
			err:  errors.New("something else"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRateLimitedError(tt.err); got != tt.want {
				t.Errorf("IsRateLimitedError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsServerErrorFunc(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "APIError server error",
			err:  &APIError{StatusCode: 500},
			want: true,
		},
		{
			name: "other error",
			err:  errors.New("something else"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsServerErrorFunc(tt.err); got != tt.want {
				t.Errorf("IsServerErrorFunc() = %v, want %v", got, tt.want)
			}
		})
	}
}
