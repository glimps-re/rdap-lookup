package schema

import (
	"testing"

	"github.com/glimps-re/rdap-lookup/internal/rdap"
)

func TestTransformDomain(t *testing.T) {
	tests := []struct {
		name       string
		resp       *rdap.DomainResponse
		rdapServer string
		validate   func(t *testing.T, result *SimpleDomain)
	}{
		{
			name:       "nil response",
			resp:       nil,
			rdapServer: "https://rdap.example.com",
			validate: func(t *testing.T, result *SimpleDomain) {
				if result != nil {
					t.Error("expected nil result for nil response")
				}
			},
		},
		{
			name: "basic domain",
			resp: &rdap.DomainResponse{
				LDHName:     "example.com",
				UnicodeName: "example.com",
				Status:      []string{"active", "client transfer prohibited"},
			},
			rdapServer: "https://rdap.verisign.com/com/v1",
			validate: func(t *testing.T, result *SimpleDomain) {
				if result.Name != "example.com" {
					t.Errorf("Name = %q, want %q", result.Name, "example.com")
				}
				if len(result.Status) != 2 {
					t.Errorf("Status count = %d, want %d", len(result.Status), 2)
				}
				if result.RDAPServer != "https://rdap.verisign.com/com/v1" {
					t.Errorf("RDAPServer = %q, want %q", result.RDAPServer, "https://rdap.verisign.com/com/v1")
				}
			},
		},
		{
			name: "domain with events",
			resp: &rdap.DomainResponse{
				LDHName: "example.com",
				Events: []rdap.Event{
					{EventAction: "registration", EventDate: "2020-01-15T10:00:00Z"},
					{EventAction: "expiration", EventDate: "2025-01-15T10:00:00Z"},
					{EventAction: "last changed", EventDate: "2024-06-01T12:00:00Z"},
				},
			},
			rdapServer: "",
			validate: func(t *testing.T, result *SimpleDomain) {
				if result.CreatedDate != "2020-01-15T10:00:00Z" {
					t.Errorf("CreatedDate = %q, want %q", result.CreatedDate, "2020-01-15T10:00:00Z")
				}
				if result.ExpirationDate != "2025-01-15T10:00:00Z" {
					t.Errorf("ExpirationDate = %q, want %q", result.ExpirationDate, "2025-01-15T10:00:00Z")
				}
				if result.UpdatedDate != "2024-06-01T12:00:00Z" {
					t.Errorf("UpdatedDate = %q, want %q", result.UpdatedDate, "2024-06-01T12:00:00Z")
				}
			},
		},
		{
			name: "domain with entities",
			resp: &rdap.DomainResponse{
				LDHName: "example.com",
				Entities: []rdap.Entity{
					{
						Handle: "REG-1",
						Roles:  []string{"registrar"},
						VCardArray: []any{
							"vcard",
							[]any{
								[]any{"fn", map[string]any{}, "text", "Example Registrar"},
								[]any{"email", map[string]any{}, "text", "abuse@registrar.com"},
							},
						},
					},
					{
						Handle: "OWNER-1",
						Roles:  []string{"registrant"},
						VCardArray: []any{
							"vcard",
							[]any{
								[]any{"fn", map[string]any{}, "text", "John Owner"},
								[]any{"adr", map[string]any{}, "text", []any{"", "", "Street", "City", "State", "Zip", "US"}},
							},
						},
					},
				},
			},
			rdapServer: "",
			validate: func(t *testing.T, result *SimpleDomain) {
				if result.Registrar == nil {
					t.Fatal("Registrar is nil")
				}
				if result.Registrar.Name != "Example Registrar" {
					t.Errorf("Registrar.Name = %q, want %q", result.Registrar.Name, "Example Registrar")
				}
				if result.Registrant == nil {
					t.Fatal("Registrant is nil")
				}
				if result.Registrant.Name != "John Owner" {
					t.Errorf("Registrant.Name = %q, want %q", result.Registrant.Name, "John Owner")
				}
				if result.Registrant.Country != "US" {
					t.Errorf("Registrant.Country = %q, want %q", result.Registrant.Country, "US")
				}
			},
		},
		{
			name: "domain with nameservers",
			resp: &rdap.DomainResponse{
				LDHName: "example.com",
				Nameservers: []rdap.Nameserver{
					{
						LDHName: "ns1.example.com",
						IPAddresses: &rdap.IPAddrs{
							V4: []string{"192.0.2.1"},
							V6: []string{"2001:db8::1"},
						},
					},
					{
						LDHName: "ns2.example.com",
					},
				},
			},
			rdapServer: "",
			validate: func(t *testing.T, result *SimpleDomain) {
				if len(result.Nameservers) != 2 {
					t.Fatalf("Nameservers count = %d, want %d", len(result.Nameservers), 2)
				}
				if result.Nameservers[0].Name != "ns1.example.com" {
					t.Errorf("Nameservers[0].Name = %q, want %q", result.Nameservers[0].Name, "ns1.example.com")
				}
				if len(result.Nameservers[0].IPv4) != 1 || result.Nameservers[0].IPv4[0] != "192.0.2.1" {
					t.Errorf("Nameservers[0].IPv4 = %v, want %v", result.Nameservers[0].IPv4, []string{"192.0.2.1"})
				}
			},
		},
		{
			name: "domain with DNSSEC",
			resp: &rdap.DomainResponse{
				LDHName: "example.com",
				SecureDNS: &rdap.SecureDNS{
					ZoneSigned:       boolPtr(true),
					DelegationSigned: boolPtr(true),
				},
			},
			rdapServer: "",
			validate: func(t *testing.T, result *SimpleDomain) {
				if result.DNSSEC == nil {
					t.Fatal("DNSSEC is nil")
				}
				if !result.DNSSEC.Signed {
					t.Error("DNSSEC.Signed = false, want true")
				}
				if !result.DNSSEC.DelegationSigned {
					t.Error("DNSSEC.DelegationSigned = false, want true")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TransformDomain(tt.resp, tt.rdapServer)
			tt.validate(t, result)
		})
	}
}

func TestFormatEventDate(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"2024-01-15T10:30:00Z", "2024-01-15T10:30:00Z"},
		{"2024-01-15T10:30:00+05:00", "2024-01-15T05:30:00Z"},
		{"2024-01-15", "2024-01-15T00:00:00Z"},
		{"invalid-date", "invalid-date"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := formatEventDate(tt.input)
			if result != tt.expected {
				t.Errorf("formatEventDate(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func boolPtr(b bool) *bool {
	return &b
}
