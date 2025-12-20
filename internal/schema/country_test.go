package schema

import (
	"testing"

	"github.com/glimps-re/rdap-lookup/internal/rdap"
)

func TestExtractCountryFromDomain(t *testing.T) {
	tests := []struct {
		name     string
		resp     *rdap.DomainResponse
		expected string
	}{
		{
			name:     "nil response",
			resp:     nil,
			expected: "",
		},
		{
			name:     "empty entities",
			resp:     &rdap.DomainResponse{},
			expected: "",
		},
		{
			name: "registrant with country",
			resp: &rdap.DomainResponse{
				Entities: []rdap.Entity{
					{
						Roles: []string{"registrant"},
						VCardArray: []any{
							"vcard",
							[]any{
								[]any{"adr", map[string]any{}, "text", []any{"", "", "", "", "", "", "FR"}},
							},
						},
					},
				},
			},
			expected: "FR",
		},
		{
			name: "admin contact when no registrant",
			resp: &rdap.DomainResponse{
				Entities: []rdap.Entity{
					{
						Roles: []string{"administrative"},
						VCardArray: []any{
							"vcard",
							[]any{
								[]any{"adr", map[string]any{}, "text", []any{"", "", "", "", "", "", "DE"}},
							},
						},
					},
				},
			},
			expected: "DE",
		},
		{
			name: "registrant priority over admin",
			resp: &rdap.DomainResponse{
				Entities: []rdap.Entity{
					{
						Roles: []string{"administrative"},
						VCardArray: []any{
							"vcard",
							[]any{
								[]any{"adr", map[string]any{}, "text", []any{"", "", "", "", "", "", "DE"}},
							},
						},
					},
					{
						Roles: []string{"registrant"},
						VCardArray: []any{
							"vcard",
							[]any{
								[]any{"adr", map[string]any{}, "text", []any{"", "", "", "", "", "", "US"}},
							},
						},
					},
				},
			},
			expected: "US",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractCountryFromDomain(tt.resp)
			if result != tt.expected {
				t.Errorf("ExtractCountryFromDomain() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestExtractCountryFromIP(t *testing.T) {
	tests := []struct {
		name     string
		resp     *rdap.IPResponse
		expected string
	}{
		{
			name:     "nil response",
			resp:     nil,
			expected: "",
		},
		{
			name: "country field set",
			resp: &rdap.IPResponse{
				Country: "US",
			},
			expected: "US",
		},
		{
			name: "country from entity when field empty",
			resp: &rdap.IPResponse{
				Entities: []rdap.Entity{
					{
						Roles: []string{"registrant"},
						VCardArray: []any{
							"vcard",
							[]any{
								[]any{"adr", map[string]any{}, "text", []any{"", "", "", "", "", "", "JP"}},
							},
						},
					},
				},
			},
			expected: "JP",
		},
		{
			name: "country field priority over entity",
			resp: &rdap.IPResponse{
				Country: "AU",
				Entities: []rdap.Entity{
					{
						Roles: []string{"registrant"},
						VCardArray: []any{
							"vcard",
							[]any{
								[]any{"adr", map[string]any{}, "text", []any{"", "", "", "", "", "", "JP"}},
							},
						},
					},
				},
			},
			expected: "AU",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractCountryFromIP(tt.resp)
			if result != tt.expected {
				t.Errorf("ExtractCountryFromIP() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestExtractCountryFromASN(t *testing.T) {
	tests := []struct {
		name     string
		resp     *rdap.ASNResponse
		expected string
	}{
		{
			name:     "nil response",
			resp:     nil,
			expected: "",
		},
		{
			name: "country field set",
			resp: &rdap.ASNResponse{
				Country: "BR",
			},
			expected: "BR",
		},
		{
			name: "country from entity",
			resp: &rdap.ASNResponse{
				Entities: []rdap.Entity{
					{
						Roles: []string{"registrant"},
						VCardArray: []any{
							"vcard",
							[]any{
								[]any{"adr", map[string]any{}, "text", []any{"", "", "", "", "", "", "KR"}},
							},
						},
					},
				},
			},
			expected: "KR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractCountryFromASN(tt.resp)
			if result != tt.expected {
				t.Errorf("ExtractCountryFromASN() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestExtractCountryFromEntityResponse(t *testing.T) {
	tests := []struct {
		name     string
		resp     *rdap.EntityResponse
		expected string
	}{
		{
			name:     "nil response",
			resp:     nil,
			expected: "",
		},
		{
			name: "country from vCard",
			resp: &rdap.EntityResponse{
				VCardArray: []any{
					"vcard",
					[]any{
						[]any{"adr", map[string]any{}, "text", []any{"", "", "", "", "", "", "SG"}},
					},
				},
			},
			expected: "SG",
		},
		{
			name: "country from network",
			resp: &rdap.EntityResponse{
				Networks: []rdap.IPResponse{
					{Country: "NL"},
				},
			},
			expected: "NL",
		},
		{
			name: "country from ASN",
			resp: &rdap.EntityResponse{
				Autnums: []rdap.ASNResponse{
					{Country: "CH"},
				},
			},
			expected: "CH",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractCountryFromEntityResponse(tt.resp)
			if result != tt.expected {
				t.Errorf("ExtractCountryFromEntityResponse() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestNormalizeCountry(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"US", "US"},
		{"us", "US"},
		{"  US  ", "US"},
		{"United States", "US"},
		{"UNITED STATES", "US"},
		{"United States of America", "US"},
		{"UK", "UK"},
		{"United Kingdom", "GB"},
		{"Germany", "DE"},
		{"deutschland", "DE"},
		{"Japan", "JP"},
		{"Unknown Country", "UNKNOWN COUNTRY"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeCountry(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeCountry(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
