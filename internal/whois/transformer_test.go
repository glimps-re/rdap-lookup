package whois

import (
	"testing"
	"time"

	"github.com/glimps-re/rdap-lookup/internal/schema"
	"github.com/google/go-cmp/cmp"
)

func TestTransformToSimpleDomain(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		result *ParseResult
		want   *schema.SimpleDomain
	}{
		{
			name: "nil result",
		},
		{
			name:   "nil domain",
			result: &ParseResult{},
		},
		{
			name: "basic domain with dates and DNSSEC",
			result: &ParseResult{
				Domain: &ParsedDomain{
					DomainName:     "example.de",
					Status:         []string{"connect"},
					Nameservers:    []string{"ns1.example.de", "ns2.example.de"},
					CreatedDate:    utc(2000, 1, 15, 0, 0, 0),
					UpdatedDate:    utc(2024, 6, 15, 10, 30, 0),
					ExpirationDate: utc(2025, 1, 15, 0, 0, 0),
					DNSSECSigned:   new(true),
					WHOISServer:    "whois.denic.de",
				},
				Confidence: ConfidenceHigh,
				ParserName: "de",
			},
			want: &schema.SimpleDomain{
				Name:   "example.de",
				Status: []string{"connect"},
				Nameservers: []schema.SimpleNS{
					{Name: "ns1.example.de"},
					{Name: "ns2.example.de"},
				},
				CreatedDate:    "2000-01-15T00:00:00Z",
				UpdatedDate:    "2024-06-15T10:30:00Z",
				ExpirationDate: "2025-01-15T00:00:00Z",
				DNSSEC: &schema.SimpleDNSSEC{
					Signed:           true,
					DelegationSigned: true,
				},
				DataSource:  "whois",
				WHOISServer: "whois.denic.de",
				Confidence:  "high",
			},
		},
		{
			name: "with contacts",
			result: &ParseResult{
				Domain: &ParsedDomain{
					DomainName:  "example.com",
					WHOISServer: "whois.example.com",
					Registrar: &ParsedEntity{
						Name:         "Example Registrar, Inc.",
						Organization: "Example Registrar",
						Email:        "contact@registrar.com",
					},
					Registrant: &ParsedEntity{
						Name:         "John Doe",
						Organization: "Example Corp",
						Country:      "US",
					},
					AdminContact: &ParsedEntity{
						Name:  "Admin Contact",
						Email: "admin@example.com",
						Phone: "+1.5551234567",
					},
					TechContact: &ParsedEntity{
						Name:    "Tech Support",
						Street:  "123 Tech St",
						City:    "San Francisco",
						State:   "CA",
						Country: "US",
					},
				},
				Confidence: ConfidenceHigh,
				ParserName: "generic",
			},
			want: &schema.SimpleDomain{
				Name: "example.com",
				Registrar: &schema.SimpleEntity{
					Name:         "Example Registrar, Inc.",
					Organization: "Example Registrar",
					Email:        "contact@registrar.com",
				},
				Registrant: &schema.SimpleEntity{
					Name:         "John Doe",
					Organization: "Example Corp",
					Address:      "US",
					Country:      "US",
				},
				AdminContact: &schema.SimpleEntity{
					Name:  "Admin Contact",
					Email: "admin@example.com",
					Phone: "+1.5551234567",
				},
				TechContact: &schema.SimpleEntity{
					Name:    "Tech Support",
					Address: "123 Tech St, San Francisco, CA, US",
					Country: "US",
				},
				DataSource:  "whois",
				WHOISServer: "whois.example.com",
				Confidence:  "high",
			},
		},
		{
			name: "low confidence",
			result: &ParseResult{
				Domain: &ParsedDomain{
					DomainName:  "example.unknown",
					WHOISServer: "whois.nic.unknown",
				},
				Confidence: ConfidenceLow,
				ParserName: "generic",
			},
			want: &schema.SimpleDomain{
				Name:        "example.unknown",
				DataSource:  "whois",
				WHOISServer: "whois.nic.unknown",
				Confidence:  "low",
			},
		},
		{
			name: "no dates",
			result: &ParseResult{
				Domain: &ParsedDomain{
					DomainName:  "example.test",
					WHOISServer: "whois.test",
				},
				Confidence: ConfidenceLow,
			},
			want: &schema.SimpleDomain{
				Name:        "example.test",
				DataSource:  "whois",
				WHOISServer: "whois.test",
				Confidence:  "low",
			},
		},
		{
			name: "no DNSSEC",
			result: &ParseResult{
				Domain:     &ParsedDomain{DomainName: "example.test"},
				Confidence: ConfidenceHigh,
			},
			want: &schema.SimpleDomain{
				Name:       "example.test",
				DataSource: "whois",
				Confidence: "high",
			},
		},
		{
			name: "empty nameservers",
			result: &ParseResult{
				Domain: &ParsedDomain{
					DomainName:  "example.test",
					Nameservers: []string{},
				},
				Confidence: ConfidenceHigh,
			},
			want: &schema.SimpleDomain{
				Name:       "example.test",
				DataSource: "whois",
				Confidence: "high",
			},
		},
		{
			name: "preformatted address is used as is",
			result: &ParseResult{
				Domain: &ParsedDomain{
					DomainName: "example.test",
					Registrant: &ParsedEntity{
						Name:    "Test User",
						Address: "Pre-formatted Address Line",
						City:    "Should Not Use",
						Country: "XX",
					},
				},
				Confidence: ConfidenceHigh,
			},
			want: &schema.SimpleDomain{
				Name: "example.test",
				Registrant: &schema.SimpleEntity{
					Name:    "Test User",
					Address: "Pre-formatted Address Line",
					Country: "XX",
				},
				DataSource: "whois",
				Confidence: "high",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := TransformToSimpleDomain(tc.result)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("TransformToSimpleDomain() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestTransformEntity_Nil(t *testing.T) {
	result := transformEntity(nil)
	if result != nil {
		t.Error("transformEntity(nil) should return nil")
	}
}

func TestTransformEntity_AllFields(t *testing.T) {
	pe := &ParsedEntity{
		Handle:       "ABC123",
		Name:         "John Doe",
		Organization: "Example Corp",
		Email:        "john@example.com",
		Phone:        "+1.5551234567",
		Country:      "US",
		Address:      "123 Main St, New York, NY 10001",
	}

	entity := transformEntity(pe)

	if entity == nil {
		t.Fatal("transformEntity returned nil")
	}

	if entity.Handle != "ABC123" {
		t.Errorf("Handle = %q, want ABC123", entity.Handle)
	}
	if entity.Name != "John Doe" {
		t.Errorf("Name = %q, want John Doe", entity.Name)
	}
	if entity.Organization != "Example Corp" {
		t.Errorf("Organization = %q, want Example Corp", entity.Organization)
	}
	if entity.Email != "john@example.com" {
		t.Errorf("Email = %q, want john@example.com", entity.Email)
	}
	if entity.Phone != "+1.5551234567" {
		t.Errorf("Phone = %q, want +1.5551234567", entity.Phone)
	}
	if entity.Country != "US" {
		t.Errorf("Country = %q, want US", entity.Country)
	}
	if entity.Address != "123 Main St, New York, NY 10001" {
		t.Errorf("Address = %q, want 123 Main St, New York, NY 10001", entity.Address)
	}
}

func TestBuildAddress(t *testing.T) {
	tests := []struct {
		name     string
		entity   *ParsedEntity
		expected string
	}{
		{
			name: "all components",
			entity: &ParsedEntity{
				Street:     "123 Main St",
				City:       "New York",
				State:      "NY",
				PostalCode: "10001",
				Country:    "US",
			},
			expected: "123 Main St, New York, NY, 10001, US",
		},
		{
			name: "missing state",
			entity: &ParsedEntity{
				Street:     "123 Main St",
				City:       "Berlin",
				PostalCode: "10115",
				Country:    "DE",
			},
			expected: "123 Main St, Berlin, 10115, DE",
		},
		{
			name: "only country",
			entity: &ParsedEntity{
				Country: "JP",
			},
			expected: "JP",
		},
		{
			name:     "empty",
			entity:   &ParsedEntity{},
			expected: "",
		},
		{
			name: "city and country",
			entity: &ParsedEntity{
				City:    "Tokyo",
				Country: "JP",
			},
			expected: "Tokyo, JP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildAddress(tt.entity)
			if result != tt.expected {
				t.Errorf("buildAddress() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestFormatTime(t *testing.T) {
	tests := []struct {
		name     string
		input    *time.Time
		expected string
	}{
		{
			name:     "nil",
			input:    nil,
			expected: "",
		},
		{
			name: "UTC time",
			input: func() *time.Time {
				t := time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC)
				return &t
			}(),
			expected: "2024-06-15T10:30:00Z",
		},
		{
			name: "non-UTC time",
			input: func() *time.Time {
				loc, _ := time.LoadLocation("America/New_York")
				t := time.Date(2024, 6, 15, 10, 30, 0, 0, loc)
				return &t
			}(),
			expected: "2024-06-15T14:30:00Z", // Converted to UTC
		},
		{
			name: "zero time",
			input: func() *time.Time {
				t := time.Time{}
				return &t
			}(),
			expected: "0001-01-01T00:00:00Z",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatTime(tt.input)
			if result != tt.expected {
				t.Errorf("formatTime() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func BenchmarkTransformToSimpleDomain(b *testing.B) {
	created := time.Now().Add(-365 * 24 * time.Hour)
	updated := time.Now().Add(-24 * time.Hour)
	expires := time.Now().Add(365 * 24 * time.Hour)
	signed := true

	result := &ParseResult{
		Domain: &ParsedDomain{
			DomainName:     "example.de",
			Status:         []string{"connect", "ok"},
			Nameservers:    []string{"ns1.example.de", "ns2.example.de", "ns3.example.de"},
			CreatedDate:    &created,
			UpdatedDate:    &updated,
			ExpirationDate: &expires,
			DNSSECSigned:   &signed,
			WHOISServer:    "whois.denic.de",
			Registrar: &ParsedEntity{
				Name:         "Example Registrar GmbH",
				Organization: "Example Registrar",
				Email:        "contact@registrar.de",
			},
			Registrant: &ParsedEntity{
				Name:    "Domain Owner",
				Country: "DE",
			},
		},
		Confidence: ConfidenceHigh,
		ParserName: "de",
	}

	b.ResetTimer()
	for b.Loop() {
		_ = TransformToSimpleDomain(result)
	}
}
