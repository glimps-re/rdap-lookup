package rdap

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/glimps-re/rdap-lookup/internal/bootstrap"
	"github.com/glimps-re/rdap-lookup/internal/logging"
	"github.com/glimps-re/rdap-lookup/internal/metrics"
)

// createTestBootstrap creates a bootstrap with test data pointing to the test server.
func createTestBootstrap(serverURL string) *bootstrap.Bootstrap {
	b := bootstrap.NewBootstrap()

	// Add DNS entries
	b.DNS.SetTLDURLs("com", []string{serverURL})
	b.DNS.SetTLDURLs("org", []string{serverURL})
	b.DNS.SetTLDURLs("net", []string{serverURL})

	// Add IPv4 entries (errors ignored in test - valid CIDR format)
	_ = b.IPv4.AddPrefix("8.0.0.0/8", []string{serverURL})
	_ = b.IPv4.AddPrefix("192.168.0.0/16", []string{serverURL})

	// Add IPv6 entries
	_ = b.IPv6.AddPrefix("2001::/16", []string{serverURL})

	// Add ASN entries
	b.ASN.AddRange(1, 100000, []string{serverURL})

	return b
}

func TestClient_QueryDomain(t *testing.T) {
	// Create mock RDAP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/domain/example.com" {
			// Return raw RDAP JSON format expected by openrdap decoder
			w.Header().Set("Content-Type", "application/rdap+json")
			_, _ = w.Write([]byte(`{
				"objectClassName": "domain",
				"ldhName": "example.com",
				"handle": "DOM123",
				"status": ["active"]
			}`))
			return
		}
		if r.URL.Path == "/domain/notfound.com" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	var buf bytes.Buffer
	logger := logging.SetupWithWriter(logging.Config{Level: "debug", Format: "json"}, &buf)
	m := metrics.New()

	b := createTestBootstrap(server.URL + "/")
	resolver := bootstrap.NewResolver(b)

	client := NewClient(
		10*time.Second,
		WithResolver(resolver),
		WithLogger(logger),
		WithMetrics(m),
		WithMaxRetries(1),
	)

	t.Run("successful query", func(t *testing.T) {
		resp, err := client.QueryDomain(context.Background(), "example.com")
		if err != nil {
			t.Fatalf("QueryDomain failed: %v", err)
		}
		if resp.LDHName != "example.com" {
			t.Errorf("LDHName = %q, want %q", resp.LDHName, "example.com")
		}
		if resp.Handle != "DOM123" {
			t.Errorf("Handle = %q, want %q", resp.Handle, "DOM123")
		}
		if !slices.Contains(resp.Status, "active") {
			t.Error("expected status to contain 'active'")
		}
	})

	t.Run("not found", func(t *testing.T) {
		_, err := client.QueryDomain(context.Background(), "notfound.com")
		if err == nil {
			t.Fatal("expected error for not found domain")
		}
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("err = %v, want ErrNotFound", err)
		}
	})

	t.Run("empty domain", func(t *testing.T) {
		_, err := client.QueryDomain(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty domain")
		}
	})

	t.Run("domain with trailing dot", func(t *testing.T) {
		resp, err := client.QueryDomain(context.Background(), "example.com.")
		if err != nil {
			t.Fatalf("QueryDomain failed: %v", err)
		}
		if resp.LDHName != "example.com" {
			t.Errorf("LDHName = %q, want %q", resp.LDHName, "example.com")
		}
	})

	t.Run("uppercase domain normalization", func(t *testing.T) {
		resp, err := client.QueryDomain(context.Background(), "EXAMPLE.COM")
		if err != nil {
			t.Fatalf("QueryDomain failed: %v", err)
		}
		if resp.LDHName != "example.com" {
			t.Errorf("LDHName = %q, want %q", resp.LDHName, "example.com")
		}
	})
}

func TestClient_QueryIP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ip/8.8.8.8" {
			w.Header().Set("Content-Type", "application/rdap+json")
			_, _ = w.Write([]byte(`{
				"objectClassName": "ip network",
				"handle": "NET-8-0-0-0-1",
				"startAddress": "8.0.0.0",
				"endAddress": "8.255.255.255",
				"ipVersion": "v4",
				"country": "US",
				"name": "LVLT-ORG-8-8"
			}`))
			return
		}
		if r.URL.Path == "/ip/2001:4860:4860::8888" {
			w.Header().Set("Content-Type", "application/rdap+json")
			_, _ = w.Write([]byte(`{
				"objectClassName": "ip network",
				"handle": "NET6-2001-4860",
				"startAddress": "2001:4860::",
				"endAddress": "2001:4860:ffff:ffff:ffff:ffff:ffff:ffff",
				"ipVersion": "v6",
				"country": "US"
			}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	var buf bytes.Buffer
	logger := logging.SetupWithWriter(logging.Config{Level: "info", Format: "json"}, &buf)

	b := createTestBootstrap(server.URL + "/")
	resolver := bootstrap.NewResolver(b)

	client := NewClient(
		10*time.Second,
		WithResolver(resolver),
		WithLogger(logger),
		WithMaxRetries(1),
	)

	t.Run("IPv4 query", func(t *testing.T) {
		resp, err := client.QueryIP(context.Background(), "8.8.8.8")
		if err != nil {
			t.Fatalf("QueryIP failed: %v", err)
		}
		if resp.IPVersion != "v4" {
			t.Errorf("IPVersion = %q, want %q", resp.IPVersion, "v4")
		}
		if resp.Country != "US" {
			t.Errorf("Country = %q, want %q", resp.Country, "US")
		}
	})

	t.Run("IPv6 query", func(t *testing.T) {
		resp, err := client.QueryIP(context.Background(), "2001:4860:4860::8888")
		if err != nil {
			t.Fatalf("QueryIP failed: %v", err)
		}
		if resp.IPVersion != "v6" {
			t.Errorf("IPVersion = %q, want %q", resp.IPVersion, "v6")
		}
	})

	t.Run("empty IP", func(t *testing.T) {
		_, err := client.QueryIP(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty IP")
		}
	})

	t.Run("invalid IP", func(t *testing.T) {
		_, err := client.QueryIP(context.Background(), "not-an-ip")
		if err == nil {
			t.Fatal("expected error for invalid IP")
		}
	})
}

func TestClient_QueryASN(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/autnum/15169" {
			w.Header().Set("Content-Type", "application/rdap+json")
			_, _ = w.Write([]byte(`{
				"objectClassName": "autnum",
				"handle": "AS15169",
				"startAutnum": 15169,
				"endAutnum": 15169,
				"name": "GOOGLE",
				"country": "US"
			}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	var buf bytes.Buffer
	logger := logging.SetupWithWriter(logging.Config{Level: "info", Format: "json"}, &buf)

	b := createTestBootstrap(server.URL + "/")
	resolver := bootstrap.NewResolver(b)

	client := NewClient(
		10*time.Second,
		WithResolver(resolver),
		WithLogger(logger),
		WithMaxRetries(1),
	)

	t.Run("successful query", func(t *testing.T) {
		resp, err := client.QueryASN(context.Background(), 15169)
		if err != nil {
			t.Fatalf("QueryASN failed: %v", err)
		}
		if resp.Name != "GOOGLE" {
			t.Errorf("Name = %q, want %q", resp.Name, "GOOGLE")
		}
		if resp.Country != "US" {
			t.Errorf("Country = %q, want %q", resp.Country, "US")
		}
	})

	t.Run("zero ASN", func(t *testing.T) {
		_, err := client.QueryASN(context.Background(), 0)
		if err == nil {
			t.Fatal("expected error for zero ASN")
		}
	})
}

func TestClient_QueryEntity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/entity/REGISTRAR123" {
			w.Header().Set("Content-Type", "application/rdap+json")
			_, _ = w.Write([]byte(`{
				"objectClassName": "entity",
				"handle": "REGISTRAR123",
				"roles": ["registrar"]
			}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	var buf bytes.Buffer
	logger := logging.SetupWithWriter(logging.Config{Level: "info", Format: "json"}, &buf)

	client := NewClient(
		10*time.Second,
		WithLogger(logger),
		WithMaxRetries(1),
	)

	t.Run("successful query", func(t *testing.T) {
		resp, err := client.QueryEntity(context.Background(), "REGISTRAR123", server.URL+"/")
		if err != nil {
			t.Fatalf("QueryEntity failed: %v", err)
		}
		if resp.Handle != "REGISTRAR123" {
			t.Errorf("Handle = %q, want %q", resp.Handle, "REGISTRAR123")
		}
		if len(resp.Roles) != 1 || resp.Roles[0] != "registrar" {
			t.Errorf("Roles = %v, want [registrar]", resp.Roles)
		}
	})

	t.Run("empty handle", func(t *testing.T) {
		_, err := client.QueryEntity(context.Background(), "", server.URL+"/")
		if err == nil {
			t.Fatal("expected error for empty handle")
		}
	})

	t.Run("no server URL", func(t *testing.T) {
		_, err := client.QueryEntity(context.Background(), "REGISTRAR123", "")
		if err == nil {
			t.Fatal("expected error for empty server URL")
		}
	})
}

func TestClient_QueryNameserver(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/nameserver/ns1.example.com" {
			w.Header().Set("Content-Type", "application/rdap+json")
			_, _ = w.Write([]byte(`{
				"objectClassName": "nameserver",
				"ldhName": "ns1.example.com",
				"handle": "NS123",
				"ipAddresses": {
					"v4": ["192.0.2.1"],
					"v6": ["2001:db8::1"]
				}
			}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	var buf bytes.Buffer
	logger := logging.SetupWithWriter(logging.Config{Level: "info", Format: "json"}, &buf)

	b := createTestBootstrap(server.URL + "/")
	resolver := bootstrap.NewResolver(b)

	client := NewClient(
		10*time.Second,
		WithResolver(resolver),
		WithLogger(logger),
		WithMaxRetries(1),
	)

	t.Run("successful query", func(t *testing.T) {
		resp, err := client.QueryNameserver(context.Background(), "ns1.example.com")
		if err != nil {
			t.Fatalf("QueryNameserver failed: %v", err)
		}
		if resp.LDHName != "ns1.example.com" {
			t.Errorf("LDHName = %q, want %q", resp.LDHName, "ns1.example.com")
		}
		if resp.IPAddresses == nil || len(resp.IPAddresses.V4) == 0 {
			t.Error("expected IPv4 addresses")
		}
	})

	t.Run("empty nameserver", func(t *testing.T) {
		_, err := client.QueryNameserver(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty nameserver")
		}
	})
}

func TestClient_RetryLogic(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(`{
			"objectClassName": "domain",
			"ldhName": "example.com"
		}`))
	}))
	defer server.Close()

	var buf bytes.Buffer
	logger := logging.SetupWithWriter(logging.Config{Level: "debug", Format: "json"}, &buf)

	b := createTestBootstrap(server.URL + "/")
	resolver := bootstrap.NewResolver(b)

	client := NewClient(
		10*time.Second,
		WithResolver(resolver),
		WithLogger(logger),
		WithMaxRetries(3),
	)

	resp, err := client.QueryDomain(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("QueryDomain failed after retries: %v", err)
	}
	if resp.LDHName != "example.com" {
		t.Errorf("LDHName = %q, want %q", resp.LDHName, "example.com")
	}
	if attempts != 3 {
		t.Errorf("attempts = %d, want 3", attempts)
	}
}

func TestClient_RateLimiting(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	var buf bytes.Buffer
	logger := logging.SetupWithWriter(logging.Config{Level: "info", Format: "json"}, &buf)

	b := createTestBootstrap(server.URL + "/")
	resolver := bootstrap.NewResolver(b)

	client := NewClient(
		10*time.Second,
		WithResolver(resolver),
		WithLogger(logger),
		WithMaxRetries(0), // No retries
	)

	_, err := client.QueryDomain(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected error for rate limiting")
	}
	// Rate limiting error may be wrapped in ErrAllServersFailed
	if !errors.Is(err, ErrRateLimited) && !strings.Contains(err.Error(), "rate limited") {
		t.Errorf("err = %v, expected to contain rate limiting", err)
	}
}

func TestClient_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		select {
		case <-r.Context().Done():
			return
		case <-time.After(5 * time.Second):
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	var buf bytes.Buffer
	logger := logging.SetupWithWriter(logging.Config{Level: "info", Format: "json"}, &buf)

	b := createTestBootstrap(server.URL + "/")
	resolver := bootstrap.NewResolver(b)

	client := NewClient(
		10*time.Second,
		WithResolver(resolver),
		WithLogger(logger),
		WithMaxRetries(0),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := client.QueryDomain(ctx, "example.com")
	if err == nil {
		t.Fatal("expected error for context cancellation")
	}
}

func TestClient_SetResolver(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.SetupWithWriter(logging.Config{Level: "info", Format: "json"}, &buf)

	client := NewClient(10*time.Second, WithLogger(logger))

	if client.resolver != nil {
		t.Error("expected nil resolver initially")
	}

	b := bootstrap.NewBootstrap()
	resolver := bootstrap.NewResolver(b)
	client.SetResolver(resolver)

	if client.resolver == nil {
		t.Error("expected resolver to be set")
	}
}

func TestClient_Options(t *testing.T) {
	customClient := &http.Client{Timeout: 30 * time.Second}
	var buf bytes.Buffer
	logger := logging.SetupWithWriter(logging.Config{Level: "info", Format: "json"}, &buf)
	m := metrics.New()

	client := NewClient(
		10*time.Second,
		WithHTTPClient(customClient),
		WithLogger(logger),
		WithMetrics(m),
		WithMaxRetries(5),
		WithUserAgent("test-agent/1.0"),
	)

	if client.httpClient != customClient {
		t.Error("expected custom HTTP client")
	}
	if client.logger == nil {
		t.Error("expected logger to be set")
	}
	if client.metrics == nil {
		t.Error("expected metrics to be set")
	}
	if client.maxRetries != 5 {
		t.Errorf("maxRetries = %d, want 5", client.maxRetries)
	}
	if client.userAgent != "test-agent/1.0" {
		t.Errorf("userAgent = %q, want %q", client.userAgent, "test-agent/1.0")
	}
}

func TestNewClient_Defaults(t *testing.T) {
	client := NewClient(10 * time.Second)

	if client.httpClient == nil {
		t.Error("expected default HTTP client")
	}
	if client.maxRetries != 2 {
		t.Errorf("maxRetries = %d, want 2", client.maxRetries)
	}
	if client.userAgent != "rdap-lookup/1.0" {
		t.Errorf("userAgent = %q, want %q", client.userAgent, "rdap-lookup/1.0")
	}
}
