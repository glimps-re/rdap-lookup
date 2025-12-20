package rdaplookup

import "testing"

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		// Basic cases
		{
			name:  "simple domain",
			input: "example.com",
			want:  "example.com",
		},
		{
			name:  "www subdomain",
			input: "www.example.com",
			want:  "example.com",
		},
		{
			name:  "deep subdomain",
			input: "api.v2.test.example.com",
			want:  "example.com",
		},

		// Multi-part TLDs
		{
			name:  "co.uk domain",
			input: "example.co.uk",
			want:  "example.co.uk",
		},
		{
			name:  "subdomain of co.uk",
			input: "www.example.co.uk",
			want:  "example.co.uk",
		},
		{
			name:  "deep subdomain co.uk",
			input: "api.test.example.co.uk",
			want:  "example.co.uk",
		},

		// Other ccTLDs with multi-part suffixes
		{
			name:  "com.au domain",
			input: "example.com.au",
			want:  "example.com.au",
		},
		{
			name:  "subdomain of com.au",
			input: "www.example.com.au",
			want:  "example.com.au",
		},

		// Edge cases
		{
			name:  "uppercase",
			input: "WWW.EXAMPLE.COM",
			want:  "example.com",
		},
		{
			name:  "trailing dot",
			input: "www.example.com.",
			want:  "example.com",
		},
		{
			name:  "whitespace",
			input: "  www.example.com  ",
			want:  "example.com",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},

		// Public suffix only (cannot be registered)
		{
			name:  "public suffix com",
			input: "com",
			want:  "com", // Returns as-is, server will handle error
		},
		{
			name:  "public suffix co.uk",
			input: "co.uk",
			want:  "co.uk", // Returns as-is, server will handle error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeDomain(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeDomain(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsPublicSuffix(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// Public suffixes
		{"com", "com", true},
		{"co.uk", "co.uk", true},
		{"org", "org", true},
		{"gov.uk", "gov.uk", true},

		// Registrable domains (not public suffixes)
		{"example.com", "example.com", false},
		{"example.co.uk", "example.co.uk", false},
		{"google.com", "google.com", false},

		// Subdomains
		{"www.example.com", "www.example.com", false},

		// Edge cases
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsPublicSuffix(tt.input)
			if got != tt.want {
				t.Errorf("IsPublicSuffix(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
