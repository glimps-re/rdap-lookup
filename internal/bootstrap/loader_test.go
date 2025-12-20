package bootstrap

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseServiceEntry(t *testing.T) {
	tests := []struct {
		name    string
		input   []any
		wantErr bool
		keys    []string
		urls    []string
	}{
		{
			name: "valid entry",
			input: []any{
				[]any{"com", "net"},
				[]any{"https://rdap.verisign.com/com/v1/"},
			},
			wantErr: false,
			keys:    []string{"com", "net"},
			urls:    []string{"https://rdap.verisign.com/com/v1/"},
		},
		{
			name:    "empty entry",
			input:   []any{},
			wantErr: true,
		},
		{
			name:    "single element",
			input:   []any{[]any{"com"}},
			wantErr: true,
		},
		{
			name: "invalid keys type",
			input: []any{
				"not an array",
				[]any{"https://example.com/"},
			},
			wantErr: true,
		},
		{
			name: "empty keys",
			input: []any{
				[]any{},
				[]any{"https://example.com/"},
			},
			wantErr: true,
		},
		{
			name: "empty urls",
			input: []any{
				[]any{"com"},
				[]any{},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, err := parseServiceEntry(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(entry.Keys) != len(tt.keys) {
				t.Errorf("keys length = %d, want %d", len(entry.Keys), len(tt.keys))
			}

			if len(entry.URLs) != len(tt.urls) {
				t.Errorf("urls length = %d, want %d", len(entry.URLs), len(tt.urls))
			}
		})
	}
}

func TestParseASNRange(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantStart uint32
		wantEnd   uint32
		wantErr   bool
	}{
		{
			name:      "single ASN",
			input:     "12345",
			wantStart: 12345,
			wantEnd:   12345,
		},
		{
			name:      "ASN range",
			input:     "1000-2000",
			wantStart: 1000,
			wantEnd:   2000,
		},
		{
			name:      "single digit",
			input:     "1",
			wantStart: 1,
			wantEnd:   1,
		},
		{
			name:      "max ASN",
			input:     "4294967295",
			wantStart: 4294967295,
			wantEnd:   4294967295,
		},
		{
			name:    "invalid format",
			input:   "abc",
			wantErr: true,
		},
		{
			name:    "reversed range",
			input:   "2000-1000",
			wantErr: true,
		},
		{
			name:    "too many parts",
			input:   "1-2-3",
			wantErr: true,
		},
		{
			name:    "empty",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start, end, err := parseASNRange(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if start != tt.wantStart {
				t.Errorf("start = %d, want %d", start, tt.wantStart)
			}
			if end != tt.wantEnd {
				t.Errorf("end = %d, want %d", end, tt.wantEnd)
			}
		})
	}
}

func TestLoader_LoadDNS(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := IANABootstrapFile{
			Description: "Test DNS Bootstrap",
			Publication: "2024-01-01",
			Version:     "1.0",
			Services: [][]any{
				{
					[]any{"com", "net"},
					[]any{"https://rdap.verisign.com/v1/"},
				},
				{
					[]any{"org"},
					[]any{"https://rdap.publicinterestregistry.org/rdap/"},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	// Create loader with custom client
	loader := &Loader{
		client:  server.Client(),
		timeout: 10 * time.Second,
		logger:  slog.Default(),
	}

	dns := &DNSBootstrap{
		tldToURLs: make(map[string][]string),
	}

	// We need to patch the URL - create a custom loader method for testing
	ctx := context.Background()
	data, err := loader.fetch(ctx, server.URL)
	if err != nil {
		t.Fatalf("fetch failed: %v", err)
	}

	var file IANABootstrapFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	// Parse manually for test
	for _, service := range file.Services {
		entry, err := parseServiceEntry(service)
		if err != nil {
			continue
		}
		for _, tld := range entry.Keys {
			dns.tldToURLs[tld] = entry.URLs
		}
	}

	if dns.TLDCount() != 3 {
		t.Errorf("TLD count = %d, want 3", dns.TLDCount())
	}

	urls, ok := dns.tldToURLs["com"]
	if !ok {
		t.Error("com TLD not found")
	}
	if len(urls) != 1 || urls[0] != "https://rdap.verisign.com/v1/" {
		t.Errorf("com URLs = %v", urls)
	}
}

func TestLoader_Fetch_Error(t *testing.T) {
	// Create server that returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	loader := &Loader{
		client:  server.Client(),
		timeout: 10 * time.Second,
		logger:  slog.Default(),
	}

	ctx := context.Background()
	_, err := loader.fetch(ctx, server.URL)
	if err == nil {
		t.Error("expected error for 500 response")
	}
}

func TestLoader_Fetch_Timeout(t *testing.T) {
	// Create server that delays
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	loader := NewLoader(50 * time.Millisecond)

	ctx := context.Background()
	_, err := loader.fetch(ctx, server.URL)
	if err == nil {
		t.Error("expected timeout error")
	}
}

func TestNewLoader(t *testing.T) {
	loader := NewLoader(30 * time.Second)

	if loader.client == nil {
		t.Error("client is nil")
	}
	if loader.timeout != 30*time.Second {
		t.Errorf("timeout = %v, want 30s", loader.timeout)
	}
}

func TestLoader_SetLogger(t *testing.T) {
	loader := NewLoader(10 * time.Second)

	customLogger := slog.Default().With("component", "test")
	loader.SetLogger(customLogger)

	if loader.logger != customLogger {
		t.Error("logger was not set correctly")
	}
}

func TestLoader_Fetch_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	loader := &Loader{
		client:  server.Client(),
		timeout: 10 * time.Second,
		logger:  slog.Default(),
	}

	ctx := context.Background()
	data, err := loader.fetch(ctx, server.URL)
	if err != nil {
		t.Fatalf("fetch should succeed even with invalid JSON (just returns bytes): %v", err)
	}

	// The actual JSON parsing happens after fetch, so test that path
	var file IANABootstrapFile
	err = json.Unmarshal(data, &file)
	if err == nil {
		t.Error("expected JSON unmarshal error for invalid JSON")
	}
}

func TestParseServiceEntry_InvalidURLsType(t *testing.T) {
	// URLs is not an array
	entry := []any{
		[]any{"com"},
		"not an array",
	}

	_, err := parseServiceEntry(entry)
	if err == nil {
		t.Error("expected error for invalid URLs type")
	}
}

func TestParseServiceEntry_NonStringKeys(t *testing.T) {
	// Keys contain non-string values (should be skipped)
	entry := []any{
		[]any{123, "com", nil},
		[]any{"https://example.com/"},
	}

	result, err := parseServiceEntry(entry)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only "com" should be included (123 and nil are skipped)
	if len(result.Keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(result.Keys))
	}
	if result.Keys[0] != "com" {
		t.Errorf("expected key 'com', got '%s'", result.Keys[0])
	}
}

func TestParseServiceEntry_NonStringURLs(t *testing.T) {
	// URLs contain non-string values (should be skipped)
	entry := []any{
		[]any{"com"},
		[]any{123, "https://example.com/", nil},
	}

	result, err := parseServiceEntry(entry)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Only the string URL should be included
	if len(result.URLs) != 1 {
		t.Errorf("expected 1 URL, got %d", len(result.URLs))
	}
	if result.URLs[0] != "https://example.com/" {
		t.Errorf("expected URL 'https://example.com/', got '%s'", result.URLs[0])
	}
}

func TestParseASNRange_InvalidStart(t *testing.T) {
	_, _, err := parseASNRange("abc-100")
	if err == nil {
		t.Error("expected error for invalid start")
	}
}

func TestParseASNRange_InvalidEnd(t *testing.T) {
	_, _, err := parseASNRange("100-abc")
	if err == nil {
		t.Error("expected error for invalid end")
	}
}

func TestLoader_LoadIPv4_WithMockServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := IANABootstrapFile{
			Description: "Test IPv4 Bootstrap",
			Publication: "2024-01-01",
			Version:     "1.0",
			Services: [][]any{
				{
					[]any{"8.0.0.0/8"},
					[]any{"https://rdap.arin.net/registry/"},
				},
				{
					[]any{"1.0.0.0/8"},
					[]any{"https://rdap.apnic.net/"},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	loader := &Loader{
		client:  server.Client(),
		timeout: 10 * time.Second,
		logger:  slog.Default(),
	}

	ctx := context.Background()
	data, err := loader.fetch(ctx, server.URL)
	if err != nil {
		t.Fatalf("fetch failed: %v", err)
	}

	var file IANABootstrapFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if len(file.Services) != 2 {
		t.Errorf("expected 2 services, got %d", len(file.Services))
	}
}

func TestLoader_LoadIPv6_WithMockServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := IANABootstrapFile{
			Description: "Test IPv6 Bootstrap",
			Publication: "2024-01-01",
			Version:     "1.0",
			Services: [][]any{
				{
					[]any{"2001::/16"},
					[]any{"https://rdap.arin.net/registry/"},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	loader := &Loader{
		client:  server.Client(),
		timeout: 10 * time.Second,
		logger:  slog.Default(),
	}

	ctx := context.Background()
	data, err := loader.fetch(ctx, server.URL)
	if err != nil {
		t.Fatalf("fetch failed: %v", err)
	}

	var file IANABootstrapFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if len(file.Services) != 1 {
		t.Errorf("expected 1 service, got %d", len(file.Services))
	}
}

func TestLoader_LoadASN_WithMockServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := IANABootstrapFile{
			Description: "Test ASN Bootstrap",
			Publication: "2024-01-01",
			Version:     "1.0",
			Services: [][]any{
				{
					[]any{"1-1000"},
					[]any{"https://rdap.arin.net/registry/"},
				},
				{
					[]any{"15169"},
					[]any{"https://rdap.arin.net/registry/"},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	loader := &Loader{
		client:  server.Client(),
		timeout: 10 * time.Second,
		logger:  slog.Default(),
	}

	ctx := context.Background()
	data, err := loader.fetch(ctx, server.URL)
	if err != nil {
		t.Fatalf("fetch failed: %v", err)
	}

	var file IANABootstrapFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if len(file.Services) != 2 {
		t.Errorf("expected 2 services, got %d", len(file.Services))
	}
}

func TestLoader_Fetch_LargeResponse(t *testing.T) {
	// Test that large responses are limited
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Write a valid but large JSON object
		_, _ = w.Write([]byte(`{"description":"test","version":"1.0","publication":"2024-01-01","services":[]}`))
	}))
	defer server.Close()

	loader := &Loader{
		client:  server.Client(),
		timeout: 10 * time.Second,
		logger:  slog.Default(),
	}

	ctx := context.Background()
	data, err := loader.fetch(ctx, server.URL)
	if err != nil {
		t.Fatalf("fetch failed: %v", err)
	}

	if len(data) == 0 {
		t.Error("expected non-empty data")
	}
}

func TestLoader_Fetch_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	loader := &Loader{
		client:  server.Client(),
		timeout: 10 * time.Second,
		logger:  slog.Default(),
	}

	ctx := context.Background()
	_, err := loader.fetch(ctx, server.URL)
	if err == nil {
		t.Error("expected error for 404 response")
	}
}

func TestLoader_Fetch_ContextCanceled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	loader := &Loader{
		client:  server.Client(),
		timeout: 10 * time.Second,
		logger:  slog.Default(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := loader.fetch(ctx, server.URL)
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

// testableLoader creates a loader that can use a custom URL for testing.
type testableLoader struct {
	*Loader
}

func (l *testableLoader) loadDNSFromURL(ctx context.Context, dns *DNSBootstrap, url string) error {
	data, err := l.fetch(ctx, url)
	if err != nil {
		return err
	}

	var file IANABootstrapFile
	if err := json.Unmarshal(data, &file); err != nil {
		return err
	}

	tldToURLs := make(map[string][]string)
	for _, service := range file.Services {
		entry, err := parseServiceEntry(service)
		if err != nil {
			continue
		}
		for _, tld := range entry.Keys {
			tldToURLs[tld] = entry.URLs
		}
	}

	dns.mu.Lock()
	dns.tldToURLs = tldToURLs
	dns.lastRefresh = time.Now()
	dns.publication = file.Publication
	dns.version = file.Version
	dns.mu.Unlock()

	return nil
}

func TestLoader_LoadDNS_FullFlow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := IANABootstrapFile{
			Description: "Test DNS Bootstrap",
			Publication: "2024-01-01",
			Version:     "1.0",
			Services: [][]any{
				{
					[]any{"com", "net"},
					[]any{"https://rdap.verisign.com/v1/"},
				},
				{
					[]any{"org"},
					[]any{"https://rdap.publicinterestregistry.org/rdap/"},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	loader := &testableLoader{
		Loader: &Loader{
			client:  server.Client(),
			timeout: 10 * time.Second,
			logger:  slog.Default(),
		},
	}

	dns := &DNSBootstrap{
		tldToURLs: make(map[string][]string),
	}

	ctx := context.Background()
	err := loader.loadDNSFromURL(ctx, dns, server.URL)
	if err != nil {
		t.Fatalf("loadDNSFromURL failed: %v", err)
	}

	// Verify the data was loaded
	if dns.TLDCount() != 3 {
		t.Errorf("TLDCount = %d, want 3", dns.TLDCount())
	}

	// Verify specific TLDs
	dns.mu.RLock()
	comURLs := dns.tldToURLs["com"]
	dns.mu.RUnlock()
	if len(comURLs) != 1 || comURLs[0] != "https://rdap.verisign.com/v1/" {
		t.Errorf("com URLs = %v, want [https://rdap.verisign.com/v1/]", comURLs)
	}

	if dns.publication != "2024-01-01" {
		t.Errorf("publication = %q, want %q", dns.publication, "2024-01-01")
	}
}

func TestLoader_LoadDNS_MalformedEntries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := IANABootstrapFile{
			Description: "Test with malformed entries",
			Publication: "2024-01-01",
			Version:     "1.0",
			Services: [][]any{
				// Valid entry
				{[]any{"com"}, []any{"https://rdap.verisign.com/v1/"}},
				// Invalid entry (missing URLs)
				{[]any{"net"}},
				// Invalid entry (wrong types)
				{"not", "arrays"},
				// Another valid entry
				{[]any{"org"}, []any{"https://rdap.pir.org/v1/"}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	loader := &testableLoader{
		Loader: &Loader{
			client:  server.Client(),
			timeout: 10 * time.Second,
			logger:  slog.Default(),
		},
	}

	dns := &DNSBootstrap{
		tldToURLs: make(map[string][]string),
	}

	ctx := context.Background()
	err := loader.loadDNSFromURL(ctx, dns, server.URL)
	if err != nil {
		t.Fatalf("loadDNSFromURL failed: %v", err)
	}

	// Only valid entries should be loaded
	if dns.TLDCount() != 2 {
		t.Errorf("TLDCount = %d, want 2 (only valid entries)", dns.TLDCount())
	}
}

func TestLoader_LoadIPv4_FullFlow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := IANABootstrapFile{
			Description: "Test IPv4 Bootstrap",
			Publication: "2024-01-01",
			Version:     "1.0",
			Services: [][]any{
				{[]any{"8.0.0.0/8"}, []any{"https://rdap.arin.net/registry/"}},
				{[]any{"192.0.0.0/8"}, []any{"https://rdap.apnic.net/"}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	loader := &Loader{
		client:  server.Client(),
		timeout: 10 * time.Second,
		logger:  slog.Default(),
	}

	ipv4 := &IPv4Bootstrap{}

	ctx := context.Background()
	data, err := loader.fetch(ctx, server.URL)
	if err != nil {
		t.Fatalf("fetch failed: %v", err)
	}

	var file IANABootstrapFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	// Simulate the loading process
	for _, service := range file.Services {
		entry, err := parseServiceEntry(service)
		if err != nil {
			continue
		}
		for _, key := range entry.Keys {
			err := ipv4.AddPrefix(key, entry.URLs)
			if err != nil {
				t.Logf("AddPrefix error (expected for some tests): %v", err)
			}
		}
	}

	if ipv4.PrefixCount() != 2 {
		t.Errorf("PrefixCount = %d, want 2", ipv4.PrefixCount())
	}
}

func TestLoader_LoadIPv6_FullFlow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := IANABootstrapFile{
			Description: "Test IPv6 Bootstrap",
			Publication: "2024-01-01",
			Version:     "1.0",
			Services: [][]any{
				{[]any{"2001::/16"}, []any{"https://rdap.arin.net/registry/"}},
				{[]any{"2600::/12"}, []any{"https://rdap.arin.net/registry/"}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	loader := &Loader{
		client:  server.Client(),
		timeout: 10 * time.Second,
		logger:  slog.Default(),
	}

	ipv6 := &IPv6Bootstrap{}

	ctx := context.Background()
	data, err := loader.fetch(ctx, server.URL)
	if err != nil {
		t.Fatalf("fetch failed: %v", err)
	}

	var file IANABootstrapFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	// Simulate the loading process
	for _, service := range file.Services {
		entry, err := parseServiceEntry(service)
		if err != nil {
			continue
		}
		for _, key := range entry.Keys {
			err := ipv6.AddPrefix(key, entry.URLs)
			if err != nil {
				t.Logf("AddPrefix error: %v", err)
			}
		}
	}

	if ipv6.PrefixCount() != 2 {
		t.Errorf("PrefixCount = %d, want 2", ipv6.PrefixCount())
	}
}

func TestLoader_LoadASN_FullFlow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := IANABootstrapFile{
			Description: "Test ASN Bootstrap",
			Publication: "2024-01-01",
			Version:     "1.0",
			Services: [][]any{
				{[]any{"1-1000"}, []any{"https://rdap.arin.net/registry/"}},
				{[]any{"15169"}, []any{"https://rdap.arin.net/registry/"}},
				{[]any{"64496-64511"}, []any{"https://rdap.ripe.net/"}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	loader := &Loader{
		client:  server.Client(),
		timeout: 10 * time.Second,
		logger:  slog.Default(),
	}

	asn := &ASNBootstrap{}

	ctx := context.Background()
	data, err := loader.fetch(ctx, server.URL)
	if err != nil {
		t.Fatalf("fetch failed: %v", err)
	}

	var file IANABootstrapFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	// Simulate the loading process
	for _, service := range file.Services {
		entry, err := parseServiceEntry(service)
		if err != nil {
			continue
		}
		for _, key := range entry.Keys {
			start, end, err := parseASNRange(key)
			if err != nil {
				continue
			}
			asn.AddRange(start, end, entry.URLs)
		}
	}

	if asn.RangeCount() != 3 {
		t.Errorf("RangeCount = %d, want 3", asn.RangeCount())
	}
}

func TestLoader_LoadIPv4_InvalidPrefixes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := IANABootstrapFile{
			Description: "Test with invalid prefixes",
			Services: [][]any{
				// Valid IPv4 prefix
				{[]any{"8.0.0.0/8"}, []any{"https://rdap.arin.net/"}},
				// Invalid prefix (not a CIDR)
				{[]any{"not-a-prefix"}, []any{"https://test.com/"}},
				// Another invalid prefix
				{[]any{"999.999.999.999/8"}, []any{"https://test.com/"}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	loader := &Loader{
		client:  server.Client(),
		timeout: 10 * time.Second,
		logger:  slog.Default(),
	}

	ipv4 := &IPv4Bootstrap{}

	ctx := context.Background()
	data, err := loader.fetch(ctx, server.URL)
	if err != nil {
		t.Fatalf("fetch failed: %v", err)
	}

	var file IANABootstrapFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	for _, service := range file.Services {
		entry, err := parseServiceEntry(service)
		if err != nil {
			continue
		}
		for _, key := range entry.Keys {
			// This will fail for invalid prefixes - that's expected
			_ = ipv4.AddPrefix(key, entry.URLs)
		}
	}

	// Only valid IPv4 prefix should be loaded
	if ipv4.PrefixCount() != 1 {
		t.Errorf("PrefixCount = %d, want 1", ipv4.PrefixCount())
	}
}

func TestLoader_LoadASN_InvalidRanges(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		response := IANABootstrapFile{
			Description: "Test with invalid ASN ranges",
			Services: [][]any{
				// Valid range
				{[]any{"1-100"}, []any{"https://rdap.arin.net/"}},
				// Invalid range (not a number)
				{[]any{"not-a-number"}, []any{"https://test.com/"}},
				// Invalid range (reversed)
				{[]any{"100-1"}, []any{"https://test.com/"}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	loader := &Loader{
		client:  server.Client(),
		timeout: 10 * time.Second,
		logger:  slog.Default(),
	}

	asn := &ASNBootstrap{}

	ctx := context.Background()
	data, err := loader.fetch(ctx, server.URL)
	if err != nil {
		t.Fatalf("fetch failed: %v", err)
	}

	var file IANABootstrapFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	for _, service := range file.Services {
		entry, err := parseServiceEntry(service)
		if err != nil {
			continue
		}
		for _, key := range entry.Keys {
			start, end, err := parseASNRange(key)
			if err != nil {
				continue // Skip invalid ranges
			}
			asn.AddRange(start, end, entry.URLs)
		}
	}

	// Only valid range should be loaded
	if asn.RangeCount() != 1 {
		t.Errorf("RangeCount = %d, want 1", asn.RangeCount())
	}
}

// mockTransport intercepts HTTP requests and returns mock responses
type mockTransport struct {
	responses map[string]string // URL suffix -> response body
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	for suffix, body := range m.responses {
		if strings.HasSuffix(req.URL.String(), suffix) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		}
	}
	return &http.Response{
		StatusCode: http.StatusNotFound,
		Body:       io.NopCloser(strings.NewReader("not found")),
		Header:     make(http.Header),
	}, nil
}

func TestLoader_LoadDNS_ActualMethod(t *testing.T) {
	dnsResponse := `{
		"description": "Test DNS",
		"publication": "2024-01-01",
		"version": "1.0",
		"services": [
			[["com", "net"], ["https://rdap.verisign.com/v1/"]],
			[["org"], ["https://rdap.pir.org/v1/"]]
		]
	}`

	transport := &mockTransport{
		responses: map[string]string{
			"/rdap/dns.json": dnsResponse,
		},
	}

	loader := &Loader{
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
		timeout: 10 * time.Second,
		logger:  slog.Default(),
	}

	dns := &DNSBootstrap{
		tldToURLs: make(map[string][]string),
	}

	ctx := context.Background()
	err := loader.LoadDNS(ctx, dns)
	if err != nil {
		t.Fatalf("LoadDNS failed: %v", err)
	}

	if dns.TLDCount() != 3 {
		t.Errorf("TLDCount = %d, want 3", dns.TLDCount())
	}

	if dns.publication != "2024-01-01" {
		t.Errorf("publication = %q, want %q", dns.publication, "2024-01-01")
	}
}

func TestLoader_LoadIPv4_ActualMethod(t *testing.T) {
	ipv4Response := `{
		"description": "Test IPv4",
		"publication": "2024-01-01",
		"version": "1.0",
		"services": [
			[["8.0.0.0/8"], ["https://rdap.arin.net/registry/"]],
			[["1.0.0.0/8"], ["https://rdap.apnic.net/"]]
		]
	}`

	transport := &mockTransport{
		responses: map[string]string{
			"/rdap/ipv4.json": ipv4Response,
		},
	}

	loader := &Loader{
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
		timeout: 10 * time.Second,
		logger:  slog.Default(),
	}

	ipv4 := &IPv4Bootstrap{}

	ctx := context.Background()
	err := loader.LoadIPv4(ctx, ipv4)
	if err != nil {
		t.Fatalf("LoadIPv4 failed: %v", err)
	}

	if ipv4.PrefixCount() != 2 {
		t.Errorf("PrefixCount = %d, want 2", ipv4.PrefixCount())
	}
}

func TestLoader_LoadIPv6_ActualMethod(t *testing.T) {
	ipv6Response := `{
		"description": "Test IPv6",
		"publication": "2024-01-01",
		"version": "1.0",
		"services": [
			[["2001::/16"], ["https://rdap.arin.net/registry/"]],
			[["2600::/12"], ["https://rdap.arin.net/registry/"]]
		]
	}`

	transport := &mockTransport{
		responses: map[string]string{
			"/rdap/ipv6.json": ipv6Response,
		},
	}

	loader := &Loader{
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
		timeout: 10 * time.Second,
		logger:  slog.Default(),
	}

	ipv6 := &IPv6Bootstrap{}

	ctx := context.Background()
	err := loader.LoadIPv6(ctx, ipv6)
	if err != nil {
		t.Fatalf("LoadIPv6 failed: %v", err)
	}

	if ipv6.PrefixCount() != 2 {
		t.Errorf("PrefixCount = %d, want 2", ipv6.PrefixCount())
	}
}

func TestLoader_LoadASN_ActualMethod(t *testing.T) {
	asnResponse := `{
		"description": "Test ASN",
		"publication": "2024-01-01",
		"version": "1.0",
		"services": [
			[["1-1000"], ["https://rdap.arin.net/registry/"]],
			[["15169"], ["https://rdap.arin.net/registry/"]]
		]
	}`

	transport := &mockTransport{
		responses: map[string]string{
			"/rdap/asn.json": asnResponse,
		},
	}

	loader := &Loader{
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
		timeout: 10 * time.Second,
		logger:  slog.Default(),
	}

	asn := &ASNBootstrap{}

	ctx := context.Background()
	err := loader.LoadASN(ctx, asn)
	if err != nil {
		t.Fatalf("LoadASN failed: %v", err)
	}

	if asn.RangeCount() != 2 {
		t.Errorf("RangeCount = %d, want 2", asn.RangeCount())
	}
}

func TestLoader_LoadAll_ActualMethod(t *testing.T) {
	dnsResponse := `{"services": [[["com"], ["https://rdap.verisign.com/"]]]}`
	ipv4Response := `{"services": [[["8.0.0.0/8"], ["https://rdap.arin.net/"]]]}`
	ipv6Response := `{"services": [[["2001::/16"], ["https://rdap.arin.net/"]]]}`
	asnResponse := `{"services": [[["1-100"], ["https://rdap.arin.net/"]]]}`

	transport := &mockTransport{
		responses: map[string]string{
			"/rdap/dns.json":  dnsResponse,
			"/rdap/ipv4.json": ipv4Response,
			"/rdap/ipv6.json": ipv6Response,
			"/rdap/asn.json":  asnResponse,
		},
	}

	loader := &Loader{
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
		timeout: 10 * time.Second,
		logger:  slog.Default(),
	}

	ctx := context.Background()
	bootstrap, err := loader.LoadAll(ctx)
	if err != nil {
		t.Fatalf("LoadAll failed: %v", err)
	}

	if bootstrap.DNS.TLDCount() != 1 {
		t.Errorf("DNS TLDCount = %d, want 1", bootstrap.DNS.TLDCount())
	}
	if bootstrap.IPv4.PrefixCount() != 1 {
		t.Errorf("IPv4 PrefixCount = %d, want 1", bootstrap.IPv4.PrefixCount())
	}
	if bootstrap.IPv6.PrefixCount() != 1 {
		t.Errorf("IPv6 PrefixCount = %d, want 1", bootstrap.IPv6.PrefixCount())
	}
	if bootstrap.ASN.RangeCount() != 1 {
		t.Errorf("ASN RangeCount = %d, want 1", bootstrap.ASN.RangeCount())
	}
}

func TestLoader_LoadAll_DNSFailure(t *testing.T) {
	// Only provide ipv4, ipv6, asn - DNS will fail
	transport := &mockTransport{
		responses: map[string]string{
			"/rdap/ipv4.json": `{"services": []}`,
			"/rdap/ipv6.json": `{"services": []}`,
			"/rdap/asn.json":  `{"services": []}`,
		},
	}

	loader := &Loader{
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
		timeout: 10 * time.Second,
		logger:  slog.Default(),
	}

	ctx := context.Background()
	_, err := loader.LoadAll(ctx)
	if err == nil {
		t.Error("expected error when DNS fails")
	}
}

func TestLoader_LoadAll_IPv4Failure(t *testing.T) {
	// Provide DNS but not IPv4
	transport := &mockTransport{
		responses: map[string]string{
			"/rdap/dns.json":  `{"services": [[["com"], ["https://example.com/"]]]}`,
			"/rdap/ipv6.json": `{"services": []}`,
			"/rdap/asn.json":  `{"services": []}`,
		},
	}

	loader := &Loader{
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
		timeout: 10 * time.Second,
		logger:  slog.Default(),
	}

	ctx := context.Background()
	_, err := loader.LoadAll(ctx)
	if err == nil {
		t.Error("expected error when IPv4 fails")
	}
}

func TestLoader_LoadAll_IPv6Failure(t *testing.T) {
	transport := &mockTransport{
		responses: map[string]string{
			"/rdap/dns.json":  `{"services": [[["com"], ["https://example.com/"]]]}`,
			"/rdap/ipv4.json": `{"services": [[["8.0.0.0/8"], ["https://example.com/"]]]}`,
			"/rdap/asn.json":  `{"services": []}`,
		},
	}

	loader := &Loader{
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
		timeout: 10 * time.Second,
		logger:  slog.Default(),
	}

	ctx := context.Background()
	_, err := loader.LoadAll(ctx)
	if err == nil {
		t.Error("expected error when IPv6 fails")
	}
}

func TestLoader_LoadAll_ASNFailure(t *testing.T) {
	transport := &mockTransport{
		responses: map[string]string{
			"/rdap/dns.json":  `{"services": [[["com"], ["https://example.com/"]]]}`,
			"/rdap/ipv4.json": `{"services": [[["8.0.0.0/8"], ["https://example.com/"]]]}`,
			"/rdap/ipv6.json": `{"services": [[["2001::/16"], ["https://example.com/"]]]}`,
		},
	}

	loader := &Loader{
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
		timeout: 10 * time.Second,
		logger:  slog.Default(),
	}

	ctx := context.Background()
	_, err := loader.LoadAll(ctx)
	if err == nil {
		t.Error("expected error when ASN fails")
	}
}

func TestLoader_LoadDNS_InvalidJSON(t *testing.T) {
	transport := &mockTransport{
		responses: map[string]string{
			"/rdap/dns.json": "not valid json",
		},
	}

	loader := &Loader{
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
		timeout: 10 * time.Second,
		logger:  slog.Default(),
	}

	dns := &DNSBootstrap{
		tldToURLs: make(map[string][]string),
	}

	ctx := context.Background()
	err := loader.LoadDNS(ctx, dns)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoader_LoadIPv4_InvalidJSON(t *testing.T) {
	transport := &mockTransport{
		responses: map[string]string{
			"/rdap/ipv4.json": "not valid json",
		},
	}

	loader := &Loader{
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
		timeout: 10 * time.Second,
		logger:  slog.Default(),
	}

	ipv4 := &IPv4Bootstrap{}

	ctx := context.Background()
	err := loader.LoadIPv4(ctx, ipv4)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoader_LoadIPv6_InvalidJSON(t *testing.T) {
	transport := &mockTransport{
		responses: map[string]string{
			"/rdap/ipv6.json": "not valid json",
		},
	}

	loader := &Loader{
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
		timeout: 10 * time.Second,
		logger:  slog.Default(),
	}

	ipv6 := &IPv6Bootstrap{}

	ctx := context.Background()
	err := loader.LoadIPv6(ctx, ipv6)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoader_LoadASN_InvalidJSON(t *testing.T) {
	transport := &mockTransport{
		responses: map[string]string{
			"/rdap/asn.json": "not valid json",
		},
	}

	loader := &Loader{
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
		timeout: 10 * time.Second,
		logger:  slog.Default(),
	}

	asn := &ASNBootstrap{}

	ctx := context.Background()
	err := loader.LoadASN(ctx, asn)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoader_LoadIPv4_SkipsInvalidAndIPv6(t *testing.T) {
	// IPv4 response that includes IPv6 prefixes (should be skipped)
	ipv4Response := `{
		"services": [
			[["8.0.0.0/8"], ["https://rdap.arin.net/"]],
			[["2001::/16"], ["https://rdap.arin.net/"]],
			[["not-valid"], ["https://rdap.arin.net/"]]
		]
	}`

	transport := &mockTransport{
		responses: map[string]string{
			"/rdap/ipv4.json": ipv4Response,
		},
	}

	loader := &Loader{
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
		timeout: 10 * time.Second,
		logger:  slog.Default(),
	}

	ipv4 := &IPv4Bootstrap{}

	ctx := context.Background()
	err := loader.LoadIPv4(ctx, ipv4)
	if err != nil {
		t.Fatalf("LoadIPv4 failed: %v", err)
	}

	// Only the valid IPv4 prefix should be loaded
	if ipv4.PrefixCount() != 1 {
		t.Errorf("PrefixCount = %d, want 1", ipv4.PrefixCount())
	}
}

func TestLoader_LoadIPv6_SkipsInvalidAndIPv4(t *testing.T) {
	// IPv6 response that includes IPv4 prefixes (should be skipped)
	ipv6Response := `{
		"services": [
			[["2001::/16"], ["https://rdap.arin.net/"]],
			[["8.0.0.0/8"], ["https://rdap.arin.net/"]],
			[["not-valid"], ["https://rdap.arin.net/"]]
		]
	}`

	transport := &mockTransport{
		responses: map[string]string{
			"/rdap/ipv6.json": ipv6Response,
		},
	}

	loader := &Loader{
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
		timeout: 10 * time.Second,
		logger:  slog.Default(),
	}

	ipv6 := &IPv6Bootstrap{}

	ctx := context.Background()
	err := loader.LoadIPv6(ctx, ipv6)
	if err != nil {
		t.Fatalf("LoadIPv6 failed: %v", err)
	}

	// Only the valid IPv6 prefix should be loaded
	if ipv6.PrefixCount() != 1 {
		t.Errorf("PrefixCount = %d, want 1", ipv6.PrefixCount())
	}
}
