package schema

import (
	"testing"

	"github.com/glimps-re/rdap-lookup/internal/rdap"
)

func TestTransformIP(t *testing.T) {
	tests := []struct {
		name       string
		resp       *rdap.IPResponse
		rdapServer string
		validate   func(t *testing.T, result *SimpleIP)
	}{
		{
			name:       "nil response",
			resp:       nil,
			rdapServer: "https://rdap.arin.net/registry",
			validate: func(t *testing.T, result *SimpleIP) {
				if result != nil {
					t.Error("expected nil result for nil response")
				}
			},
		},
		{
			name: "basic IPv4 network",
			resp: &rdap.IPResponse{
				Handle:       "NET-192-0-2-0-1",
				StartAddress: "192.0.2.0",
				EndAddress:   "192.0.2.255",
				IPVersion:    "v4",
				Name:         "EXAMPLE-NET",
				Type:         "DIRECT ALLOCATION",
				Country:      "US",
			},
			rdapServer: "https://rdap.arin.net/registry",
			validate: func(t *testing.T, result *SimpleIP) {
				if result.StartAddress != "192.0.2.0" {
					t.Errorf("StartAddress = %q, want %q", result.StartAddress, "192.0.2.0")
				}
				if result.EndAddress != "192.0.2.255" {
					t.Errorf("EndAddress = %q, want %q", result.EndAddress, "192.0.2.255")
				}
				if result.IPVersion != "v4" {
					t.Errorf("IPVersion = %q, want %q", result.IPVersion, "v4")
				}
				if result.Country != "US" {
					t.Errorf("Country = %q, want %q", result.Country, "US")
				}
				if result.Name != "EXAMPLE-NET" {
					t.Errorf("Name = %q, want %q", result.Name, "EXAMPLE-NET")
				}
			},
		},
		{
			name: "IPv6 network",
			resp: &rdap.IPResponse{
				Handle:       "NET6-2001-DB8-1",
				StartAddress: "2001:db8::",
				EndAddress:   "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
				IPVersion:    "v6",
				Name:         "EXAMPLE-NET-V6",
			},
			rdapServer: "",
			validate: func(t *testing.T, result *SimpleIP) {
				if result.IPVersion != "v6" {
					t.Errorf("IPVersion = %q, want %q", result.IPVersion, "v6")
				}
				if result.StartAddress != "2001:db8::" {
					t.Errorf("StartAddress = %q, want %q", result.StartAddress, "2001:db8::")
				}
			},
		},
		{
			name: "network with CIDR",
			resp: &rdap.IPResponse{
				StartAddress: "192.0.2.0",
				EndAddress:   "192.0.2.255",
				IPVersion:    "v4",
				CIDR0Cidrs: []rdap.CIDR{
					{V4Prefix: "192.0.2.0", Length: 24},
				},
			},
			rdapServer: "",
			validate: func(t *testing.T, result *SimpleIP) {
				if len(result.CIDR) != 1 {
					t.Fatalf("CIDR count = %d, want %d", len(result.CIDR), 1)
				}
				if result.CIDR[0] != "192.0.2.0/24" {
					t.Errorf("CIDR[0] = %q, want %q", result.CIDR[0], "192.0.2.0/24")
				}
			},
		},
		{
			name: "network with events",
			resp: &rdap.IPResponse{
				StartAddress: "192.0.2.0",
				EndAddress:   "192.0.2.255",
				IPVersion:    "v4",
				Events: []rdap.Event{
					{EventAction: "registration", EventDate: "2010-05-01T00:00:00Z"},
					{EventAction: "last changed", EventDate: "2023-11-15T12:00:00Z"},
				},
			},
			rdapServer: "",
			validate: func(t *testing.T, result *SimpleIP) {
				if result.CreatedDate != "2010-05-01T00:00:00Z" {
					t.Errorf("CreatedDate = %q, want %q", result.CreatedDate, "2010-05-01T00:00:00Z")
				}
				if result.UpdatedDate != "2023-11-15T12:00:00Z" {
					t.Errorf("UpdatedDate = %q, want %q", result.UpdatedDate, "2023-11-15T12:00:00Z")
				}
			},
		},
		{
			name: "network with entities",
			resp: &rdap.IPResponse{
				StartAddress: "192.0.2.0",
				EndAddress:   "192.0.2.255",
				IPVersion:    "v4",
				Entities: []rdap.Entity{
					{
						Handle: "ABUSE-1",
						Roles:  []string{"abuse"},
						VCardArray: []any{
							"vcard",
							[]any{
								[]any{"fn", map[string]any{}, "text", "Abuse Contact"},
								[]any{"email", map[string]any{}, "text", "abuse@example.com"},
							},
						},
					},
					{
						Handle: "TECH-1",
						Roles:  []string{"technical"},
						VCardArray: []any{
							"vcard",
							[]any{
								[]any{"fn", map[string]any{}, "text", "Tech Contact"},
							},
						},
					},
				},
			},
			rdapServer: "",
			validate: func(t *testing.T, result *SimpleIP) {
				if result.AbuseContact == nil {
					t.Fatal("AbuseContact is nil")
				}
				if result.AbuseContact.Name != "Abuse Contact" {
					t.Errorf("AbuseContact.Name = %q, want %q", result.AbuseContact.Name, "Abuse Contact")
				}
				if result.AbuseContact.Email != "abuse@example.com" {
					t.Errorf("AbuseContact.Email = %q, want %q", result.AbuseContact.Email, "abuse@example.com")
				}
				if result.TechContact == nil {
					t.Fatal("TechContact is nil")
				}
				if result.TechContact.Name != "Tech Contact" {
					t.Errorf("TechContact.Name = %q, want %q", result.TechContact.Name, "Tech Contact")
				}
			},
		},
		{
			name: "network with country from entity",
			resp: &rdap.IPResponse{
				StartAddress: "192.0.2.0",
				EndAddress:   "192.0.2.255",
				IPVersion:    "v4",
				Entities: []rdap.Entity{
					{
						Handle: "REG-1",
						Roles:  []string{"registrant"},
						VCardArray: []any{
							"vcard",
							[]any{
								[]any{"fn", map[string]any{}, "text", "Registrant"},
								[]any{"adr", map[string]any{}, "text", []any{"", "", "", "", "", "", "DE"}},
							},
						},
					},
				},
			},
			rdapServer: "",
			validate: func(t *testing.T, result *SimpleIP) {
				if result.Country != "DE" {
					t.Errorf("Country = %q, want %q", result.Country, "DE")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TransformIP(tt.resp, tt.rdapServer)
			tt.validate(t, result)
		})
	}
}

func TestFormatCIDR(t *testing.T) {
	tests := []struct {
		prefix   string
		length   int
		expected string
	}{
		{"192.0.2.0", 24, "192.0.2.0/24"},
		{"10.0.0.0", 8, "10.0.0.0/8"},
		{"2001:db8::", 32, "2001:db8::/32"},
		{"192.0.2.0", 0, "192.0.2.0"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatCIDR(tt.prefix, tt.length)
			if result != tt.expected {
				t.Errorf("formatCIDR(%q, %d) = %q, want %q", tt.prefix, tt.length, result, tt.expected)
			}
		})
	}
}

func TestItoa(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{0, "0"},
		{1, "1"},
		{24, "24"},
		{128, "128"},
		{-5, "-5"},
		{12345, "12345"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := itoa(tt.input)
			if result != tt.expected {
				t.Errorf("itoa(%d) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
