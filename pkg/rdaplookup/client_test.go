package rdaplookup

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		wantErr bool
	}{
		{
			name:    "valid URL",
			baseURL: "http://localhost:8080",
			wantErr: false,
		},
		{
			name:    "valid URL with trailing slash",
			baseURL: "http://localhost:8080/",
			wantErr: false,
		},
		{
			name:    "valid HTTPS URL",
			baseURL: "https://api.example.com/v1",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.baseURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && client == nil {
				t.Error("NewClient() returned nil client")
			}
		})
	}
}

func TestClient_Options(t *testing.T) {
	customHTTPClient := &http.Client{Timeout: 5 * time.Second}

	client, err := NewClient(
		"http://localhost:8080",
		WithTimeout(10*time.Second),
		WithMaxRetries(5),
		WithUserAgent("test-agent/1.0"),
		WithMaxResponseSize(1024*1024),
		WithHTTPClient(customHTTPClient),
	)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	if client.maxRetries != 5 {
		t.Errorf("maxRetries = %d, want 5", client.maxRetries)
	}
	if client.userAgent != "test-agent/1.0" {
		t.Errorf("userAgent = %s, want test-agent/1.0", client.userAgent)
	}
	if client.maxResponseSize != 1024*1024 {
		t.Errorf("maxResponseSize = %d, want %d", client.maxResponseSize, 1024*1024)
	}
}

func TestClient_LookupDomain(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		options  []Option
		domain   string
		body     string
		wantPath string
		want     *DomainResponse
	}{
		{
			name:     "decodes the full response",
			domain:   "example.com",
			body:     `{"name":"example.com","status":["active"],"created_date":"2020-01-01T00:00:00Z","country":"US","dnssec":{"signed":true,"delegation_signed":true}}`,
			wantPath: "/api/v1/domain/example.com",
			want: &DomainResponse{
				Name:        "example.com",
				Status:      []string{"active"},
				CreatedDate: "2020-01-01T00:00:00Z",
				Country:     "US",
				DNSSEC: &SimpleDNSSEC{
					Signed:           true,
					DelegationSigned: true,
				},
			},
		},
		{
			name:     "data source",
			domain:   "example.de",
			body:     `{"name":"example.de","data_source":"whois","whois_server":"whois.denic.de","confidence":"high"}`,
			wantPath: "/api/v1/domain/example.de",
			want: &DomainResponse{
				Name:        "example.de",
				DataSource:  "whois",
				WHOISServer: "whois.denic.de",
				Confidence:  "high",
			},
		},
		{
			name:     "normalization reduces a subdomain to the registrable domain",
			domain:   "www.example.com",
			body:     `{"name":"example.com"}`,
			wantPath: "/api/v1/domain/example.com",
			want:     &DomainResponse{Name: "example.com"},
		},
		{
			name:     "normalization disabled keeps the subdomain",
			options:  []Option{WithDomainNormalization(false)},
			domain:   "www.example.com",
			body:     `{"name":"www.example.com"}`,
			wantPath: "/api/v1/domain/www.example.com",
			want:     &DomainResponse{Name: "www.example.com"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tc.wantPath {
					t.Errorf("path = %s, want %s", r.URL.Path, tc.wantPath)
				}
				if r.Method != http.MethodGet {
					t.Errorf("method = %s, want %s", r.Method, http.MethodGet)
				}
				w.Header().Set("Content-Type", "application/json")
				if _, err := w.Write([]byte(tc.body)); err != nil {
					t.Errorf("write response: %v", err)
				}
			}))
			defer server.Close()

			client, err := NewClient(server.URL, tc.options...)
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}

			got, err := client.LookupDomain(t.Context(), tc.domain)
			if err != nil {
				t.Fatalf("LookupDomain() error = %v", err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("DomainResponse mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestClient_LookupIP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/ip/8.8.8.8" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		resp := IPResponse{
			StartAddress: "8.8.8.0",
			EndAddress:   "8.8.8.255",
			Name:         "GOOGLE",
			Country:      "US",
			CIDR:         []string{"8.8.8.0/24"},
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, _ := NewClient(server.URL)
	ctx := context.Background()

	resp, err := client.LookupIP(ctx, "8.8.8.8")
	if err != nil {
		t.Fatalf("LookupIP() error = %v", err)
	}

	if resp.Name != "GOOGLE" {
		t.Errorf("Name = %s, want GOOGLE", resp.Name)
	}
	if len(resp.CIDR) != 1 || resp.CIDR[0] != "8.8.8.0/24" {
		t.Errorf("CIDR = %v, want [8.8.8.0/24]", resp.CIDR)
	}
}

func TestClient_LookupASN(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/asn/15169" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		resp := ASNResponse{
			StartAutnum: 15169,
			EndAutnum:   15169,
			Name:        "GOOGLE",
			Country:     "US",
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, _ := NewClient(server.URL)
	ctx := context.Background()

	resp, err := client.LookupASN(ctx, "15169")
	if err != nil {
		t.Fatalf("LookupASN() error = %v", err)
	}

	if resp.Name != "GOOGLE" {
		t.Errorf("Name = %s, want GOOGLE", resp.Name)
	}
	if resp.StartAutnum != 15169 {
		t.Errorf("StartAutnum = %d, want 15169", resp.StartAutnum)
	}
}

func TestClient_LookupEntity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/entity/ABC-123" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		serverParam := r.URL.Query().Get("server")
		if serverParam != "https://rdap.example.com" {
			t.Errorf("unexpected server param: %s", serverParam)
		}

		resp := EntityResponse{
			Handle: "ABC-123",
			Name:   "Example Entity",
			Email:  "entity@example.com",
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, _ := NewClient(server.URL)
	ctx := context.Background()

	resp, err := client.LookupEntity(ctx, "ABC-123", "https://rdap.example.com")
	if err != nil {
		t.Fatalf("LookupEntity() error = %v", err)
	}

	if resp.Handle != "ABC-123" {
		t.Errorf("Handle = %s, want ABC-123", resp.Handle)
	}
	if resp.Name != "Example Entity" {
		t.Errorf("Name = %s, want Example Entity", resp.Name)
	}
}

func TestClient_BatchLookup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/batch" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected Content-Type: %s", r.Header.Get("Content-Type"))
		}

		var req BatchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("failed to decode request: %v", err)
		}

		if len(req.Queries) != 2 {
			t.Errorf("expected 2 queries, got %d", len(req.Queries))
		}

		resp := BatchResponse{
			Results: []BatchResult{
				{Type: "domain", Value: "example.com", Cached: true},
				{Type: "ip", Value: "8.8.8.8", Cached: false},
			},
			Stats: &BatchStats{
				Total:      2,
				Success:    2,
				Errors:     0,
				CacheHits:  1,
				DurationMs: 100,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, _ := NewClient(server.URL)
	ctx := context.Background()

	req := &BatchRequest{
		Queries: []BatchQuery{
			{Type: "domain", Value: "example.com"},
			{Type: "ip", Value: "8.8.8.8"},
		},
	}

	resp, err := client.BatchLookup(ctx, req)
	if err != nil {
		t.Fatalf("BatchLookup() error = %v", err)
	}

	if len(resp.Results) != 2 {
		t.Errorf("Results length = %d, want 2", len(resp.Results))
	}
	if resp.Stats.Total != 2 {
		t.Errorf("Stats.Total = %d, want 2", resp.Stats.Total)
	}
	if resp.Stats.CacheHits != 1 {
		t.Errorf("Stats.CacheHits = %d, want 1", resp.Stats.CacheHits)
	}
}

func TestClient_Health(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, _ := NewClient(server.URL)
	ctx := context.Background()

	err := client.Health(ctx)
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
}

func TestClient_Ready(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ready" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, _ := NewClient(server.URL)
	ctx := context.Background()

	err := client.Ready(ctx)
	if err != nil {
		t.Fatalf("Ready() error = %v", err)
	}
}

func TestClient_Meta(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/meta" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		resp := MetaResponse{
			Component: "rdap-lookup",
			Version:   "1.0.0",
			Hostname:  "server1",
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, _ := NewClient(server.URL)
	ctx := context.Background()

	resp, err := client.Meta(ctx)
	if err != nil {
		t.Fatalf("Meta() error = %v", err)
	}

	if resp.Component != "rdap-lookup" {
		t.Errorf("Component = %s, want rdap-lookup", resp.Component)
	}
	if resp.Version != "1.0.0" {
		t.Errorf("Version = %s, want 1.0.0", resp.Version)
	}
}

func TestClient_ErrorHandling(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		statusCode     int
		responseBody   string
		wantStatusCode int
		wantCode       string
		wantNotFound   bool
	}{
		{
			name:           "not found",
			statusCode:     404,
			responseBody:   `{"error":{"code":"NOT_FOUND","message":"Domain not found"}}`,
			wantStatusCode: 404,
			wantCode:       "NOT_FOUND",
			wantNotFound:   true,
		},
		{
			name:           "no source",
			statusCode:     404,
			responseBody:   `{"error":{"code":"NO_SOURCE","message":"No registry source found for domain"}}`,
			wantStatusCode: 404,
			wantCode:       "NO_SOURCE",
		},
		{
			name:           "rate limited",
			statusCode:     429,
			responseBody:   `{"error":{"code":"RATE_LIMITED","message":"Too many requests"}}`,
			wantStatusCode: 429,
			wantCode:       "RATE_LIMITED",
		},
		{
			name:           "server error",
			statusCode:     500,
			responseBody:   `{"error":{"code":"INTERNAL_ERROR","message":"Internal server error"}}`,
			wantStatusCode: 500,
			wantCode:       "INTERNAL_ERROR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.statusCode)
				if _, err := w.Write([]byte(tt.responseBody)); err != nil {
					t.Errorf("write response: %v", err)
				}
			}))
			defer server.Close()

			client, err := NewClient(server.URL, WithMaxRetries(0))
			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}

			_, err = client.LookupDomain(t.Context(), "test.com")
			if err == nil {
				t.Fatal("expected error, got nil")
			}

			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("expected *APIError, got %T", err)
			}

			if apiErr.StatusCode != tt.wantStatusCode {
				t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, tt.wantStatusCode)
			}
			if apiErr.Code != tt.wantCode {
				t.Errorf("Code = %s, want %s", apiErr.Code, tt.wantCode)
			}
			if got := IsNotFoundError(err); got != tt.wantNotFound {
				t.Errorf("IsNotFoundError() = %v, want %v", got, tt.wantNotFound)
			}
		})
	}
}

func TestClient_Retry(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		resp := DomainResponse{Name: "example.com"}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client, _ := NewClient(server.URL, WithMaxRetries(3))
	ctx := context.Background()

	resp, err := client.LookupDomain(ctx, "example.com")
	if err != nil {
		t.Fatalf("LookupDomain() error = %v", err)
	}

	if resp.Name != "example.com" {
		t.Errorf("Name = %s, want example.com", resp.Name)
	}
	if attempts != 3 {
		t.Errorf("attempts = %d, want 3", attempts)
	}
}

func TestClient_NoRetryOn4xx(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"code":"INVALID_REQUEST","message":"Bad request"}}`))
	}))
	defer server.Close()

	client, _ := NewClient(server.URL, WithMaxRetries(3))
	ctx := context.Background()

	_, err := client.LookupDomain(ctx, "example.com")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if attempts != 1 {
		t.Errorf("attempts = %d, want 1 (no retries on 4xx)", attempts)
	}
}

func TestClient_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, _ := NewClient(server.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := client.LookupDomain(ctx, "example.com")
	if err == nil {
		t.Fatal("expected error due to context cancellation")
	}
}
