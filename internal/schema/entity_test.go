package schema

import (
	"testing"

	"github.com/glimps-re/rdap-lookup/internal/rdap"
)

func TestTransformEntityResponse(t *testing.T) {
	tests := []struct {
		name       string
		resp       *rdap.EntityResponse
		rdapServer string
		validate   func(t *testing.T, result *SimpleEntityFull)
	}{
		{
			name:       "nil response",
			resp:       nil,
			rdapServer: "https://rdap.arin.net/registry",
			validate: func(t *testing.T, result *SimpleEntityFull) {
				if result != nil {
					t.Error("expected nil result for nil response")
				}
			},
		},
		{
			name: "basic entity",
			resp: &rdap.EntityResponse{
				Handle: "ORG-EXAMPLE-1",
				Roles:  []string{"registrant"},
				Status: []string{"validated"},
				VCardArray: []any{
					"vcard",
					[]any{
						[]any{"fn", map[string]any{}, "text", "Example Organization"},
						[]any{"org", map[string]any{}, "text", "Example Inc."},
						[]any{"email", map[string]any{}, "text", "contact@example.com"},
						[]any{"tel", map[string]any{}, "uri", "+1-555-555-5555"},
						[]any{"adr", map[string]any{}, "text", []any{"", "", "123 Main St", "Anytown", "CA", "12345", "US"}},
					},
				},
			},
			rdapServer: "https://rdap.arin.net/registry",
			validate: func(t *testing.T, result *SimpleEntityFull) {
				if result.Handle != "ORG-EXAMPLE-1" {
					t.Errorf("Handle = %q, want %q", result.Handle, "ORG-EXAMPLE-1")
				}
				if result.Name != "Example Organization" {
					t.Errorf("Name = %q, want %q", result.Name, "Example Organization")
				}
				if result.Organization != "Example Inc." {
					t.Errorf("Organization = %q, want %q", result.Organization, "Example Inc.")
				}
				if result.Email != "contact@example.com" {
					t.Errorf("Email = %q, want %q", result.Email, "contact@example.com")
				}
				if result.Phone != "+1-555-555-5555" {
					t.Errorf("Phone = %q, want %q", result.Phone, "+1-555-555-5555")
				}
				if result.Country != "US" {
					t.Errorf("Country = %q, want %q", result.Country, "US")
				}
				if len(result.Roles) != 1 || result.Roles[0] != "registrant" {
					t.Errorf("Roles = %v, want %v", result.Roles, []string{"registrant"})
				}
			},
		},
		{
			name: "entity with events",
			resp: &rdap.EntityResponse{
				Handle: "ORG-1",
				Events: []rdap.Event{
					{EventAction: "registration", EventDate: "2010-01-01T00:00:00Z"},
					{EventAction: "last changed", EventDate: "2024-06-15T10:00:00Z"},
				},
			},
			rdapServer: "",
			validate: func(t *testing.T, result *SimpleEntityFull) {
				if result.CreatedDate != "2010-01-01T00:00:00Z" {
					t.Errorf("CreatedDate = %q, want %q", result.CreatedDate, "2010-01-01T00:00:00Z")
				}
				if result.UpdatedDate != "2024-06-15T10:00:00Z" {
					t.Errorf("UpdatedDate = %q, want %q", result.UpdatedDate, "2024-06-15T10:00:00Z")
				}
			},
		},
		{
			name: "entity with related networks",
			resp: &rdap.EntityResponse{
				Handle: "ORG-1",
				Networks: []rdap.IPResponse{
					{
						Handle:       "NET-192-0-2-0-1",
						StartAddress: "192.0.2.0",
						EndAddress:   "192.0.2.255",
						Name:         "EXAMPLE-NET",
						Country:      "US",
					},
					{
						Handle:       "NET6-2001-DB8-1",
						StartAddress: "2001:db8::",
						EndAddress:   "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
						Name:         "EXAMPLE-NET-V6",
					},
				},
			},
			rdapServer: "",
			validate: func(t *testing.T, result *SimpleEntityFull) {
				if len(result.RelatedIPNets) != 2 {
					t.Fatalf("RelatedIPNets count = %d, want %d", len(result.RelatedIPNets), 2)
				}
				if result.RelatedIPNets[0].Handle != "NET-192-0-2-0-1" {
					t.Errorf("RelatedIPNets[0].Handle = %q, want %q", result.RelatedIPNets[0].Handle, "NET-192-0-2-0-1")
				}
				if result.RelatedIPNets[0].StartAddress != "192.0.2.0" {
					t.Errorf("RelatedIPNets[0].StartAddress = %q, want %q", result.RelatedIPNets[0].StartAddress, "192.0.2.0")
				}
			},
		},
		{
			name: "entity with related ASNs",
			resp: &rdap.EntityResponse{
				Handle: "ORG-1",
				Autnums: []rdap.ASNResponse{
					{
						Handle:      "AS64496",
						StartAutnum: 64496,
						Name:        "EXAMPLE-AS",
						Country:     "US",
					},
					{
						Handle:      "AS64497",
						StartAutnum: 64497,
						Name:        "EXAMPLE-AS-2",
					},
				},
			},
			rdapServer: "",
			validate: func(t *testing.T, result *SimpleEntityFull) {
				if len(result.RelatedASNs) != 2 {
					t.Fatalf("RelatedASNs count = %d, want %d", len(result.RelatedASNs), 2)
				}
				if result.RelatedASNs[0].ASN != 64496 {
					t.Errorf("RelatedASNs[0].ASN = %d, want %d", result.RelatedASNs[0].ASN, 64496)
				}
				if result.RelatedASNs[0].Name != "EXAMPLE-AS" {
					t.Errorf("RelatedASNs[0].Name = %q, want %q", result.RelatedASNs[0].Name, "EXAMPLE-AS")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TransformEntityResponse(tt.resp, tt.rdapServer)
			tt.validate(t, result)
		})
	}
}
