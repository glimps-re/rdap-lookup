package validate

import (
	"errors"
	"testing"
)

func TestNewRDAPServerValidator(t *testing.T) {
	servers := []string{
		"https://rdap.arin.net/registry/",
		"https://rdap.ripe.net/",
		"https://rdap.apnic.net/",
	}

	v := NewRDAPServerValidator(servers)

	if v.AllowedCount() != 3 {
		t.Errorf("expected 3 allowed servers, got %d", v.AllowedCount())
	}
}

func TestRDAPServerValidator_IsAllowed(t *testing.T) {
	servers := []string{
		"https://rdap.arin.net/registry/",
		"https://rdap.ripe.net/",
		"https://rdap.apnic.net/",
		"https://rdap.lacnic.net/rdap/",
		"https://rdap.afrinic.net/rdap/",
	}

	v := NewRDAPServerValidator(servers)

	tests := []struct {
		name       string
		serverURL  string
		wantErr    bool
		wantErrVal error // specific error if we care about the type
	}{
		{
			name:      "valid server from allowlist",
			serverURL: "https://rdap.arin.net/registry/",
			wantErr:   false,
		},
		{
			name:      "valid server with different path",
			serverURL: "https://rdap.arin.net/different/path",
			wantErr:   false,
		},
		{
			name:      "valid server without trailing slash",
			serverURL: "https://rdap.ripe.net",
			wantErr:   false,
		},
		{
			name:      "server not in allowlist",
			serverURL: "https://evil.example.com/rdap/",
			wantErr:   true,
		},
		{
			name:      "localhost rejected",
			serverURL: "https://localhost/rdap/",
			wantErr:   true,
		},
		{
			name:      "127.0.0.1 rejected",
			serverURL: "https://127.0.0.1/rdap/",
			wantErr:   true,
		},
		{
			name:      "private IP rejected",
			serverURL: "https://192.168.1.1/rdap/",
			wantErr:   true,
		},
		{
			name:      "cloud metadata IP rejected",
			serverURL: "http://169.254.169.254/latest/meta-data/",
			wantErr:   true,
		},
		{
			name:       "empty URL rejected",
			serverURL:  "",
			wantErr:    true,
			wantErrVal: ErrEmptyURL,
		},
		{
			name:      "HTTP scheme still matches host",
			serverURL: "http://rdap.arin.net/registry/",
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.IsAllowed(tt.serverURL)
			if tt.wantErr && err == nil {
				t.Errorf("IsAllowed(%q) = nil, want error", tt.serverURL)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("IsAllowed(%q) = %v, want nil", tt.serverURL, err)
			}
			if tt.wantErrVal != nil && !errors.Is(err, tt.wantErrVal) {
				t.Errorf("IsAllowed(%q) = %v, want %v", tt.serverURL, err, tt.wantErrVal)
			}
		})
	}
}

func TestRDAPServerValidator_UpdateAllowlist(t *testing.T) {
	// Start with initial servers
	initialServers := []string{
		"https://rdap.arin.net/",
		"https://rdap.ripe.net/",
	}

	v := NewRDAPServerValidator(initialServers)

	// Verify initial state
	if err := v.IsAllowed("https://rdap.arin.net/"); err != nil {
		t.Errorf("expected arin.net to be allowed initially, got %v", err)
	}
	if err := v.IsAllowed("https://rdap.apnic.net/"); err == nil {
		t.Error("expected apnic.net to be rejected initially")
	}

	// Update allowlist
	newServers := []string{
		"https://rdap.apnic.net/",
		"https://rdap.lacnic.net/",
	}
	v.UpdateAllowlist(newServers)

	// Verify updated state
	if err := v.IsAllowed("https://rdap.arin.net/"); err == nil {
		t.Error("expected arin.net to be rejected after update")
	}
	if err := v.IsAllowed("https://rdap.apnic.net/"); err != nil {
		t.Errorf("expected apnic.net to be allowed after update, got %v", err)
	}

	if v.AllowedCount() != 2 {
		t.Errorf("expected 2 allowed servers after update, got %d", v.AllowedCount())
	}
}

func TestNormalizeServerURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "https URL with path",
			input:   "https://rdap.arin.net/registry/",
			want:    "rdap.arin.net",
			wantErr: false,
		},
		{
			name:    "https URL without path",
			input:   "https://rdap.ripe.net",
			want:    "rdap.ripe.net",
			wantErr: false,
		},
		{
			name:    "URL without scheme",
			input:   "rdap.apnic.net/rdap/",
			want:    "rdap.apnic.net",
			wantErr: false,
		},
		{
			name:    "URL with port 443 (removed)",
			input:   "https://rdap.arin.net:443/registry/",
			want:    "rdap.arin.net",
			wantErr: false,
		},
		{
			name:    "URL with port 80 (removed)",
			input:   "http://rdap.arin.net:80/registry/",
			want:    "rdap.arin.net",
			wantErr: false,
		},
		{
			name:    "URL with non-standard port (kept)",
			input:   "https://rdap.example.com:8443/",
			want:    "rdap.example.com:8443",
			wantErr: false,
		},
		{
			name:    "uppercase hostname normalized",
			input:   "https://RDAP.ARIN.NET/",
			want:    "rdap.arin.net",
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeServerURL(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("normalizeServerURL(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("normalizeServerURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRDAPServerValidator_InvalidURLsSkipped(t *testing.T) {
	// Test that invalid URLs in bootstrap data are skipped
	servers := []string{
		"https://rdap.arin.net/",
		"",        // Empty - should be skipped
		"invalid", // No dots - should be skipped
		"https://rdap.ripe.net/",
	}

	v := NewRDAPServerValidator(servers)

	// Should only have 2 valid servers
	if v.AllowedCount() != 2 {
		t.Errorf("expected 2 allowed servers (invalid URLs skipped), got %d", v.AllowedCount())
	}

	// Valid servers should still work
	if err := v.IsAllowed("https://rdap.arin.net/"); err != nil {
		t.Errorf("expected arin.net to be allowed, got %v", err)
	}
	if err := v.IsAllowed("https://rdap.ripe.net/"); err != nil {
		t.Errorf("expected ripe.net to be allowed, got %v", err)
	}
}

func TestRDAPServerValidator_ConcurrentAccess(t *testing.T) {
	servers := []string{
		"https://rdap.arin.net/",
		"https://rdap.ripe.net/",
	}

	v := NewRDAPServerValidator(servers)

	// Run concurrent reads and writes
	done := make(chan bool)

	// Readers
	for range 10 {
		go func() {
			for range 100 {
				_ = v.IsAllowed("https://rdap.arin.net/")
				_ = v.AllowedCount()
			}
			done <- true
		}()
	}

	// Writers
	for range 5 {
		go func() {
			for range 50 {
				v.UpdateAllowlist([]string{
					"https://rdap.apnic.net/",
					"https://rdap.lacnic.net/",
				})
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for range 15 {
		<-done
	}

	// Should not panic and final state should be consistent
	count := v.AllowedCount()
	if count < 0 {
		t.Errorf("unexpected negative count: %d", count)
	}
}
