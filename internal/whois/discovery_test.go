package whois

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNormalizeTLD(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple", "com", "com"},
		{"uppercase", "COM", "com"},
		{"with leading dot", ".com", "com"},
		{"with whitespace", "  com  ", "com"},
		{"uppercase with dot", ".DE", "de"},
		{"hyphenated", "co-uk", "co-uk"},
		{"empty", "", ""},
		{"only dot", ".", ""},
		{"invalid chars", "com!", ""},
		{"spaces in middle", "c om", ""},
		{"unicode TLD", "xn--fiqs8s", "xn--fiqs8s"}, // IDN TLD for China
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeTLD(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeTLD(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestExtractTLD(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected string
	}{
		{"simple domain", "example.com", "com"},
		{"subdomain", "www.example.com", "com"},
		{"deep subdomain", "sub.www.example.com", "com"},
		{"ccTLD", "example.de", "de"},
		{"two-level TLD", "example.co.uk", "uk"},
		{"with trailing dot", "example.com.", "com"},
		{"just TLD", "com", "com"},
		{"empty", "", ""},
		{"with whitespace", "  example.com  ", "com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractTLD(tt.domain)
			if result != tt.expected {
				t.Errorf("ExtractTLD(%q) = %q, want %q", tt.domain, result, tt.expected)
			}
		})
	}
}

func TestDiscovery_NewDiscovery(t *testing.T) {
	d := NewDiscovery()

	if d.timeout != DefaultDiscoveryTimeout {
		t.Errorf("default timeout = %v, want %v", d.timeout, DefaultDiscoveryTimeout)
	}

	if d.cacheTTL != 24*time.Hour {
		t.Errorf("default cacheTTL = %v, want 24h", d.cacheTTL)
	}

	if d.cache == nil {
		t.Error("cache should not be nil")
	}
}

func TestDiscovery_NewDiscoveryWithOptions(t *testing.T) {
	customTimeout := 5 * time.Second
	customTTL := 12 * time.Hour

	d := NewDiscovery(
		WithDiscoveryTimeout(customTimeout),
		WithDiscoveryCacheTTL(customTTL),
	)

	if d.timeout != customTimeout {
		t.Errorf("timeout = %v, want %v", d.timeout, customTimeout)
	}

	if d.cacheTTL != customTTL {
		t.Errorf("cacheTTL = %v, want %v", d.cacheTTL, customTTL)
	}
}

func TestDiscovery_parseIANAResponse(t *testing.T) {
	tests := []struct {
		name           string
		response       string
		expectedServer string
		expectError    bool
	}{
		{
			name: "valid IANA response for .de",
			response: `% IANA WHOIS server
% for more information on IANA, visit http://www.iana.org

domain:       DE

organisation: DENIC eG
address:      Theodor-Stern-Kai 1
address:      60596 Frankfurt am Main
address:      Germany

contact:      administrative
name:         DENIC eG - Administrative Contact
organisation: DENIC eG

contact:      technical
name:         DENIC eG - Technical Contact
organisation: DENIC eG

nserver:      A.NIC.DE 194.246.96.1 2a02:568:0:2:0:0:0:53
nserver:      F.NIC.DE 81.91.164.5 2001:608:0:5:0:0:0:2
nserver:      L.DE.NET
nserver:      N.DE.NET
nserver:      S.DE.NET
nserver:      Z.NIC.DE 194.246.96.52 2a02:568:0:2:0:0:0:d

whois:        whois.denic.de

status:       ACTIVE
remarks:      Registration information: http://www.denic.de/

created:      1986-11-05
changed:      2024-05-13
source:       IANA`,
			expectedServer: "whois.denic.de",
			expectError:    false,
		},
		{
			name: "valid response with extra whitespace",
			response: `domain:       TEST
whois:         whois.test.example
status:       ACTIVE`,
			expectedServer: "whois.test.example",
			expectError:    false,
		},
		{
			name: "no whois field",
			response: `domain:       TEST
status:       ACTIVE`,
			expectedServer: "",
			expectError:    true,
		},
		{
			name: "empty whois field",
			response: `domain:       TEST
whois:
status:       ACTIVE`,
			expectedServer: "",
			expectError:    true,
		},
		{
			name:           "empty response",
			response:       "",
			expectedServer: "",
			expectError:    true,
		},
		{
			name: "uppercase WHOIS field",
			response: `domain:       TEST
WHOIS:        whois.upper.example`,
			expectedServer: "whois.upper.example",
			expectError:    false,
		},
	}

	d := NewDiscovery()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.response)
			server, err := d.parseIANAResponse(reader)

			if tt.expectError {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if server != tt.expectedServer {
					t.Errorf("server = %q, want %q", server, tt.expectedServer)
				}
			}
		})
	}
}

func TestDiscovery_Cache(t *testing.T) {
	d := NewDiscovery(
		WithDiscoveryCacheTTL(1 * time.Hour),
	)

	// Test setCached and getCached
	d.setCached("com", "whois.verisign-grs.com")

	server := d.getCached("com")
	if server != "whois.verisign-grs.com" {
		t.Errorf("getCached(com) = %q, want whois.verisign-grs.com", server)
	}

	// Test cache miss
	server = d.getCached("nonexistent")
	if server != "" {
		t.Errorf("getCached(nonexistent) = %q, want empty", server)
	}

	// Test CacheSize
	if d.CacheSize() != 1 {
		t.Errorf("CacheSize() = %d, want 1", d.CacheSize())
	}

	// Test ClearCache
	d.ClearCache()
	if d.CacheSize() != 0 {
		t.Errorf("CacheSize() after clear = %d, want 0", d.CacheSize())
	}

	server = d.getCached("com")
	if server != "" {
		t.Errorf("getCached(com) after clear = %q, want empty", server)
	}
}

func TestDiscovery_CacheExpiration(t *testing.T) {
	// Use very short TTL for testing
	d := NewDiscovery(
		WithDiscoveryCacheTTL(10 * time.Millisecond),
	)

	d.setCached("com", "whois.verisign-grs.com")

	// Should be cached
	server := d.getCached("com")
	if server != "whois.verisign-grs.com" {
		t.Errorf("getCached(com) = %q, want whois.verisign-grs.com", server)
	}

	// Wait for expiration
	time.Sleep(20 * time.Millisecond)

	// Should be expired
	server = d.getCached("com")
	if server != "" {
		t.Errorf("getCached(com) after expiration = %q, want empty", server)
	}
}

func TestDiscovery_DiscoverServer_InvalidTLD(t *testing.T) {
	d := NewDiscovery()
	ctx := context.Background()

	// Test with invalid TLD
	_, err := d.DiscoverServer(ctx, "")
	if !errors.Is(err, ErrInvalidTLD) {
		t.Errorf("DiscoverServer('') error = %v, want ErrInvalidTLD", err)
	}

	_, err = d.DiscoverServer(ctx, "invalid!")
	if !errors.Is(err, ErrInvalidTLD) {
		t.Errorf("DiscoverServer('invalid!') error = %v, want ErrInvalidTLD", err)
	}
}

func TestDiscovery_DiscoverServer_Cached(t *testing.T) {
	d := NewDiscovery()
	ctx := context.Background()

	// Pre-populate cache
	d.setCached("test", "whois.test.example")

	// Should return cached value without network call
	server, err := d.DiscoverServer(ctx, "test")
	if err != nil {
		t.Errorf("DiscoverServer('test') error = %v", err)
	}
	if server != "whois.test.example" {
		t.Errorf("DiscoverServer('test') = %q, want whois.test.example", server)
	}
}

// TestDiscovery_DiscoverServer_Integration tests actual IANA queries.
// This test is skipped by default as it requires network access.
// Run with: go test -run TestDiscovery_DiscoverServer_Integration -tags=integration
func TestDiscovery_DiscoverServer_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	d := NewDiscovery(
		WithDiscoveryTimeout(30 * time.Second),
	)
	ctx := context.Background()

	// Test discovering WHOIS server for .com
	server, err := d.DiscoverServer(ctx, "com")
	if err != nil {
		t.Logf("Note: Could not reach IANA WHOIS server: %v", err)
		t.Skip("skipping: IANA WHOIS server not reachable")
	}

	// .com should have a WHOIS server
	if server == "" {
		t.Error("DiscoverServer('com') returned empty server")
	}
	t.Logf("Discovered WHOIS server for .com: %s", server)

	// Second call should be cached
	d.setCached("test-cached", server)
	cachedServer, err := d.DiscoverServer(ctx, "test-cached")
	if err != nil {
		t.Errorf("DiscoverServer('test-cached') error = %v", err)
	}
	if cachedServer != server {
		t.Errorf("cached server = %q, want %q", cachedServer, server)
	}
}

func TestDiscovery_parseIANAResponse_LargeResponse(t *testing.T) {
	// Create a response that exceeds the buffer but has the whois field early
	d := NewDiscovery()

	var buf bytes.Buffer
	buf.WriteString("domain:       TEST\n")
	buf.WriteString("whois:        whois.early.example\n")

	// Add lots of padding
	for i := range 1000 {
		buf.WriteString("remark:       This is padding line number ")
		buf.WriteRune(rune('0' + i%10))
		buf.WriteString("\n")
	}

	server, err := d.parseIANAResponse(&buf)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if server != "whois.early.example" {
		t.Errorf("server = %q, want whois.early.example", server)
	}
}

func TestIsValidTLDChar(t *testing.T) {
	tests := []struct {
		char     rune
		expected bool
	}{
		{'a', true},
		{'z', true},
		{'m', true},
		{'0', true},
		{'9', true},
		{'5', true},
		{'-', true},
		{'.', true},  // dots allowed for compound TLDs like com.au
		{'A', false}, // uppercase not valid (should be normalized)
		{'_', false},
		{' ', false},
		{'!', false},
		{'@', false},
	}

	for _, tt := range tests {
		t.Run(string(tt.char), func(t *testing.T) {
			result := isValidTLDChar(tt.char)
			if result != tt.expected {
				t.Errorf("isValidTLDChar(%q) = %v, want %v", tt.char, result, tt.expected)
			}
		})
	}
}
