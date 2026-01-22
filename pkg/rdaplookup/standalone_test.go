package rdaplookup

import (
	"context"
	"testing"
	"time"
)

func TestNewStandaloneClient(t *testing.T) {
	client, err := NewStandaloneClient(
		WithStandaloneTimeout(5*time.Second),
		WithCacheSize(1024*1024),
		WithCacheTTL(1*time.Hour),
		WithStandaloneUserAgent("test-agent/1.0"),
		WithStandaloneDomainNormalization(true),
	)
	if err != nil {
		t.Fatalf("NewStandaloneClient() error = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	if client == nil {
		t.Fatal("NewStandaloneClient() returned nil")
	}
}

func TestStandaloneClient_Close(t *testing.T) {
	client, err := NewStandaloneClient()
	if err != nil {
		t.Fatalf("NewStandaloneClient() error = %v", err)
	}

	// Close should work
	if err := client.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Close should be idempotent
	if err := client.Close(); err != nil {
		t.Errorf("second Close() error = %v", err)
	}

	// Operations after close should fail
	_, err = client.LookupDomain(context.Background(), "example.com")
	if err == nil {
		t.Error("LookupDomain() after Close() should error")
	}
}

func TestStandaloneClient_ImplementsInterface(t *testing.T) {
	// Compile-time check that StandaloneClient implements RDAPClient
	var _ RDAPClient = (*StandaloneClient)(nil)
}

func TestStandaloneClient_BatchLookup_Empty(t *testing.T) {
	client, err := NewStandaloneClient()
	if err != nil {
		t.Fatalf("NewStandaloneClient() error = %v", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()

	// Empty request
	resp, err := client.BatchLookup(context.Background(), nil)
	if err != nil {
		t.Fatalf("BatchLookup(nil) error = %v", err)
	}
	if resp.Stats.Total != 0 {
		t.Errorf("BatchLookup(nil) stats.Total = %d, want 0", resp.Stats.Total)
	}

	// Empty queries
	resp, err = client.BatchLookup(context.Background(), &BatchRequest{Queries: []BatchQuery{}})
	if err != nil {
		t.Fatalf("BatchLookup(empty) error = %v", err)
	}
	if resp.Stats.Total != 0 {
		t.Errorf("BatchLookup(empty) stats.Total = %d, want 0", resp.Stats.Total)
	}
}

func TestStandaloneClient_DomainNormalization(t *testing.T) {
	client, err := NewStandaloneClient(
		WithStandaloneDomainNormalization(true),
	)
	if err != nil {
		t.Fatalf("NewStandaloneClient() error = %v", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()

	// The actual lookup will fail because bootstrap is not loaded,
	// but we're testing the normalization path.
	tests := []struct {
		input    string
		expected string
	}{
		{"www.example.com", "example.com"},
		{"api.subdomain.example.com", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{"example.com.", "example.com"},
	}

	for _, tt := range tests {
		normalized := NormalizeDomain(tt.input)
		if normalized != tt.expected {
			t.Errorf("NormalizeDomain(%q) = %q, want %q", tt.input, normalized, tt.expected)
		}
	}
}

func TestStandaloneClient_Options(t *testing.T) {
	tests := []struct {
		name    string
		options []StandaloneOption
	}{
		{
			name:    "default options",
			options: nil,
		},
		{
			name: "custom timeout",
			options: []StandaloneOption{
				WithStandaloneTimeout(30 * time.Second),
			},
		},
		{
			name: "custom cache size",
			options: []StandaloneOption{
				WithCacheSize(50 * 1024 * 1024),
			},
		},
		{
			name: "custom TTL",
			options: []StandaloneOption{
				WithCacheTTL(2 * time.Hour),
			},
		},
		{
			name: "disable normalization",
			options: []StandaloneOption{
				WithStandaloneDomainNormalization(false),
			},
		},
		{
			name: "custom user agent",
			options: []StandaloneOption{
				WithStandaloneUserAgent("custom-client/2.0"),
			},
		},
		{
			name: "all options",
			options: []StandaloneOption{
				WithStandaloneTimeout(15 * time.Second),
				WithCacheSize(25 * 1024 * 1024),
				WithCacheTTL(30 * time.Minute),
				WithNegativeTTL(5 * time.Minute),
				WithStandaloneDomainNormalization(true),
				WithStandaloneUserAgent("full-test/1.0"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewStandaloneClient(tt.options...)
			if err != nil {
				t.Fatalf("NewStandaloneClient() error = %v", err)
			}
			if err := client.Close(); err != nil {
				t.Errorf("Close() error = %v", err)
			}
		})
	}
}

func TestStandaloneDefaults(t *testing.T) {
	// Verify default constants are set to expected values
	if DefaultStandaloneTimeout != 10*time.Second {
		t.Errorf("DefaultStandaloneTimeout = %v, want 10s", DefaultStandaloneTimeout)
	}
	if DefaultCacheSize != 50*1024*1024 {
		t.Errorf("DefaultCacheSize = %d, want 50MB", DefaultCacheSize)
	}
	if DefaultCacheTTL != 24*time.Hour {
		t.Errorf("DefaultCacheTTL = %v, want 24h", DefaultCacheTTL)
	}
	if DefaultNegativeTTL != 1*time.Hour {
		t.Errorf("DefaultNegativeTTL = %v, want 1h", DefaultNegativeTTL)
	}
	if DefaultStandaloneUserAgent != "rdaplookup-standalone/1.0" {
		t.Errorf("DefaultStandaloneUserAgent = %q, want rdaplookup-standalone/1.0", DefaultStandaloneUserAgent)
	}
}

func TestStandaloneClient_ContextCancellation(t *testing.T) {
	client, err := NewStandaloneClient()
	if err != nil {
		t.Fatalf("NewStandaloneClient() error = %v", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}()

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Operations with cancelled context should fail immediately
	_, err = client.LookupDomain(ctx, "example.com")
	if err == nil {
		t.Error("LookupDomain() with cancelled context should error")
	}
}

func BenchmarkStandaloneClient_Create(b *testing.B) {
	for b.Loop() {
		client, err := NewStandaloneClient()
		if err != nil {
			b.Fatal(err)
		}
		if err := client.Close(); err != nil {
			b.Fatal(err)
		}
	}
}
