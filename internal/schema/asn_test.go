package schema

import (
	"testing"

	"github.com/glimps-re/rdap-lookup/internal/rdap"
)

func TestTransformASN(t *testing.T) {
	tests := []struct {
		name       string
		resp       *rdap.ASNResponse
		rdapServer string
		validate   func(t *testing.T, result *SimpleASN)
	}{
		{
			name:       "nil response",
			resp:       nil,
			rdapServer: "https://rdap.arin.net/registry",
			validate: func(t *testing.T, result *SimpleASN) {
				if result != nil {
					t.Error("expected nil result for nil response")
				}
			},
		},
		{
			name: "single ASN",
			resp: &rdap.ASNResponse{
				Handle:      "AS64496",
				StartAutnum: 64496,
				EndAutnum:   64496,
				Name:        "EXAMPLE-AS",
				Type:        "DIRECT ALLOCATION",
				Country:     "US",
				Status:      []string{"active"},
			},
			rdapServer: "https://rdap.arin.net/registry",
			validate: func(t *testing.T, result *SimpleASN) {
				if result.ASN != 64496 {
					t.Errorf("ASN = %d, want %d", result.ASN, 64496)
				}
				// Single ASN should not have start/end set
				if result.StartASN != 0 || result.EndASN != 0 {
					t.Errorf("StartASN/EndASN = %d/%d, want 0/0 for single ASN", result.StartASN, result.EndASN)
				}
				if result.Name != "EXAMPLE-AS" {
					t.Errorf("Name = %q, want %q", result.Name, "EXAMPLE-AS")
				}
				if result.Country != "US" {
					t.Errorf("Country = %q, want %q", result.Country, "US")
				}
			},
		},
		{
			name: "ASN range",
			resp: &rdap.ASNResponse{
				Handle:      "AS64496-64500",
				StartAutnum: 64496,
				EndAutnum:   64500,
				Name:        "EXAMPLE-AS-RANGE",
			},
			rdapServer: "",
			validate: func(t *testing.T, result *SimpleASN) {
				if result.ASN != 64496 {
					t.Errorf("ASN = %d, want %d", result.ASN, 64496)
				}
				if result.StartASN != 64496 {
					t.Errorf("StartASN = %d, want %d", result.StartASN, 64496)
				}
				if result.EndASN != 64500 {
					t.Errorf("EndASN = %d, want %d", result.EndASN, 64500)
				}
			},
		},
		{
			name: "ASN with events",
			resp: &rdap.ASNResponse{
				StartAutnum: 64496,
				EndAutnum:   64496,
				Events: []rdap.Event{
					{EventAction: "registration", EventDate: "2015-03-20T00:00:00Z"},
					{EventAction: "last changed", EventDate: "2024-01-10T08:30:00Z"},
				},
			},
			rdapServer: "",
			validate: func(t *testing.T, result *SimpleASN) {
				if result.CreatedDate != "2015-03-20T00:00:00Z" {
					t.Errorf("CreatedDate = %q, want %q", result.CreatedDate, "2015-03-20T00:00:00Z")
				}
				if result.UpdatedDate != "2024-01-10T08:30:00Z" {
					t.Errorf("UpdatedDate = %q, want %q", result.UpdatedDate, "2024-01-10T08:30:00Z")
				}
			},
		},
		{
			name: "ASN with entities",
			resp: &rdap.ASNResponse{
				StartAutnum: 64496,
				EndAutnum:   64496,
				Entities: []rdap.Entity{
					{
						Handle: "ORG-1",
						Roles:  []string{"registrant"},
						VCardArray: []any{
							"vcard",
							[]any{
								[]any{"fn", map[string]any{}, "text", "Example Organization"},
								[]any{"email", map[string]any{}, "text", "noc@example.com"},
							},
						},
					},
					{
						Handle: "ABUSE-1",
						Roles:  []string{"abuse"},
						VCardArray: []any{
							"vcard",
							[]any{
								[]any{"fn", map[string]any{}, "text", "Abuse Team"},
								[]any{"email", map[string]any{}, "text", "abuse@example.com"},
							},
						},
					},
				},
			},
			rdapServer: "",
			validate: func(t *testing.T, result *SimpleASN) {
				if result.Registrant == nil {
					t.Fatal("Registrant is nil")
				}
				if result.Registrant.Name != "Example Organization" {
					t.Errorf("Registrant.Name = %q, want %q", result.Registrant.Name, "Example Organization")
				}
				if result.AbuseContact == nil {
					t.Fatal("AbuseContact is nil")
				}
				if result.AbuseContact.Email != "abuse@example.com" {
					t.Errorf("AbuseContact.Email = %q, want %q", result.AbuseContact.Email, "abuse@example.com")
				}
			},
		},
		{
			name: "ASN with country from entity",
			resp: &rdap.ASNResponse{
				StartAutnum: 64496,
				EndAutnum:   64496,
				Entities: []rdap.Entity{
					{
						Handle: "ORG-1",
						Roles:  []string{"registrant"},
						VCardArray: []any{
							"vcard",
							[]any{
								[]any{"fn", map[string]any{}, "text", "JP Organization"},
								[]any{"adr", map[string]any{}, "text", []any{"", "", "", "", "", "", "JP"}},
							},
						},
					},
				},
			},
			rdapServer: "",
			validate: func(t *testing.T, result *SimpleASN) {
				if result.Country != "JP" {
					t.Errorf("Country = %q, want %q", result.Country, "JP")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TransformASN(tt.resp, tt.rdapServer)
			tt.validate(t, result)
		})
	}
}
