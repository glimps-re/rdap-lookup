package whois

import (
	"testing"
	"time"
)

func TestTransformToSimpleDomain_Nil(t *testing.T) {
	result := TransformToSimpleDomain(nil)
	if result != nil {
		t.Error("TransformToSimpleDomain(nil) should return nil")
	}

	result = TransformToSimpleDomain(&ParseResult{Domain: nil})
	if result != nil {
		t.Error("TransformToSimpleDomain with nil Domain should return nil")
	}
}

func TestTransformToSimpleDomain_Basic(t *testing.T) {
	created := time.Date(2000, 1, 15, 0, 0, 0, 0, time.UTC)
	updated := time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC)
	expires := time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC)
	signed := true

	result := &ParseResult{
		Domain: &ParsedDomain{
			DomainName:     "example.de",
			UnicodeName:    "",
			Status:         []string{"connect"},
			Nameservers:    []string{"ns1.example.de", "ns2.example.de"},
			CreatedDate:    &created,
			UpdatedDate:    &updated,
			ExpirationDate: &expires,
			DNSSECSigned:   &signed,
			WHOISServer:    "whois.denic.de",
		},
		Confidence: ConfidenceHigh,
		ParserName: "de",
	}

	domain := TransformToSimpleDomain(result)

	if domain == nil {
		t.Fatal("TransformToSimpleDomain returned nil")
	}

	// Check basic fields
	if domain.Name != "example.de" {
		t.Errorf("Name = %q, want example.de", domain.Name)
	}
	if domain.DataSource != "whois" {
		t.Errorf("DataSource = %q, want whois", domain.DataSource)
	}
	if domain.WHOISServer != "whois.denic.de" {
		t.Errorf("WHOISServer = %q, want whois.denic.de", domain.WHOISServer)
	}
	if domain.Confidence != "high" {
		t.Errorf("Confidence = %q, want high", domain.Confidence)
	}
	if domain.RDAPServer != "" {
		t.Errorf("RDAPServer = %q, want empty", domain.RDAPServer)
	}

	// Check status
	if len(domain.Status) != 1 || domain.Status[0] != "connect" {
		t.Errorf("Status = %v, want [connect]", domain.Status)
	}

	// Check dates
	if domain.CreatedDate != "2000-01-15T00:00:00Z" {
		t.Errorf("CreatedDate = %q, want 2000-01-15T00:00:00Z", domain.CreatedDate)
	}
	if domain.UpdatedDate != "2024-06-15T10:30:00Z" {
		t.Errorf("UpdatedDate = %q, want 2024-06-15T10:30:00Z", domain.UpdatedDate)
	}
	if domain.ExpirationDate != "2025-01-15T00:00:00Z" {
		t.Errorf("ExpirationDate = %q, want 2025-01-15T00:00:00Z", domain.ExpirationDate)
	}

	// Check nameservers
	if len(domain.Nameservers) != 2 {
		t.Errorf("len(Nameservers) = %d, want 2", len(domain.Nameservers))
	} else if domain.Nameservers[0].Name != "ns1.example.de" {
		t.Errorf("Nameservers[0].Name = %q, want ns1.example.de", domain.Nameservers[0].Name)
	}

	// Check DNSSEC
	if domain.DNSSEC == nil {
		t.Error("DNSSEC should not be nil")
	} else if !domain.DNSSEC.Signed {
		t.Error("DNSSEC.Signed should be true")
	}
}

func TestTransformToSimpleDomain_WithContacts(t *testing.T) {
	result := &ParseResult{
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
	}

	domain := TransformToSimpleDomain(result)

	if domain == nil {
		t.Fatal("TransformToSimpleDomain returned nil")
	}

	// Check registrar
	if domain.Registrar == nil {
		t.Error("Registrar should not be nil")
	} else {
		if domain.Registrar.Name != "Example Registrar, Inc." {
			t.Errorf("Registrar.Name = %q, want Example Registrar, Inc.", domain.Registrar.Name)
		}
		if domain.Registrar.Organization != "Example Registrar" {
			t.Errorf("Registrar.Organization = %q, want Example Registrar", domain.Registrar.Organization)
		}
	}

	// Check registrant
	if domain.Registrant == nil {
		t.Error("Registrant should not be nil")
	} else if domain.Registrant.Country != "US" {
		t.Errorf("Registrant.Country = %q, want US", domain.Registrant.Country)
	}

	// Check admin contact
	if domain.AdminContact == nil {
		t.Error("AdminContact should not be nil")
	} else if domain.AdminContact.Email != "admin@example.com" {
		t.Errorf("AdminContact.Email = %q, want admin@example.com", domain.AdminContact.Email)
	}

	// Check tech contact with address building
	if domain.TechContact == nil {
		t.Error("TechContact should not be nil")
	} else {
		expectedAddr := "123 Tech St, San Francisco, CA, US"
		if domain.TechContact.Address != expectedAddr {
			t.Errorf("TechContact.Address = %q, want %q", domain.TechContact.Address, expectedAddr)
		}
	}
}

func TestTransformToSimpleDomain_LowConfidence(t *testing.T) {
	result := &ParseResult{
		Domain: &ParsedDomain{
			DomainName:  "example.unknown",
			WHOISServer: "whois.nic.unknown",
		},
		Confidence: ConfidenceLow,
		ParserName: "generic",
	}

	domain := TransformToSimpleDomain(result)

	if domain == nil {
		t.Fatal("TransformToSimpleDomain returned nil")
	}

	if domain.Confidence != "low" {
		t.Errorf("Confidence = %q, want low", domain.Confidence)
	}
}

func TestTransformToSimpleDomain_NoDates(t *testing.T) {
	result := &ParseResult{
		Domain: &ParsedDomain{
			DomainName:  "example.test",
			WHOISServer: "whois.test",
		},
		Confidence: ConfidenceLow,
	}

	domain := TransformToSimpleDomain(result)

	if domain == nil {
		t.Fatal("TransformToSimpleDomain returned nil")
	}

	if domain.CreatedDate != "" {
		t.Errorf("CreatedDate = %q, want empty", domain.CreatedDate)
	}
	if domain.UpdatedDate != "" {
		t.Errorf("UpdatedDate = %q, want empty", domain.UpdatedDate)
	}
	if domain.ExpirationDate != "" {
		t.Errorf("ExpirationDate = %q, want empty", domain.ExpirationDate)
	}
}

func TestTransformToSimpleDomain_NoDNSSEC(t *testing.T) {
	result := &ParseResult{
		Domain: &ParsedDomain{
			DomainName: "example.test",
		},
		Confidence: ConfidenceHigh,
	}

	domain := TransformToSimpleDomain(result)

	if domain == nil {
		t.Fatal("TransformToSimpleDomain returned nil")
	}

	if domain.DNSSEC != nil {
		t.Error("DNSSEC should be nil when DNSSECSigned is nil")
	}
}

func TestTransformToSimpleDomain_EmptyNameservers(t *testing.T) {
	result := &ParseResult{
		Domain: &ParsedDomain{
			DomainName:  "example.test",
			Nameservers: []string{},
		},
		Confidence: ConfidenceHigh,
	}

	domain := TransformToSimpleDomain(result)

	if domain == nil {
		t.Fatal("TransformToSimpleDomain returned nil")
	}

	if len(domain.Nameservers) != 0 {
		t.Errorf("len(Nameservers) = %d, want 0", len(domain.Nameservers))
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

func TestTransformToSimpleDomain_PreformattedAddress(t *testing.T) {
	// When Address is already set, it should be used directly
	result := &ParseResult{
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
	}

	domain := TransformToSimpleDomain(result)

	if domain.Registrant.Address != "Pre-formatted Address Line" {
		t.Errorf("Address = %q, want Pre-formatted Address Line", domain.Registrant.Address)
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
