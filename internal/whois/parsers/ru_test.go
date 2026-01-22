package parsers

import (
	"testing"
)

func TestRUParser_Name(t *testing.T) {
	p := NewRUParser()
	if p.Name() != "ru" {
		t.Errorf("Name() = %q, want ru", p.Name())
	}
}

func TestRUParser_SupportsTLD(t *testing.T) {
	p := NewRUParser()

	tests := []struct {
		tld      string
		expected bool
	}{
		{"ru", true},
		{"RU", true},
		{"su", true},
		{"SU", true},
		{"rf", true},
		{"xn--p1ai", true}, // .рф in punycode
		{"com", false},
		{"de", false},
		{"russia", false},
	}

	for _, tt := range tests {
		t.Run(tt.tld, func(t *testing.T) {
			if got := p.SupportsTLD(tt.tld); got != tt.expected {
				t.Errorf("SupportsTLD(%q) = %v, want %v", tt.tld, got, tt.expected)
			}
		})
	}
}

func TestRUParser_Parse_BasicDomain(t *testing.T) {
	p := NewRUParser()

	response := `domain:        EXAMPLE.RU
nserver:       ns1.example.ru.
nserver:       ns2.example.ru.
state:         REGISTERED, DELEGATED, VERIFIED
org:           Example Organization LLC
registrar:     REGISTRAR-RU
created:       2000-01-15T00:00:00Z
paid-till:     2025-01-15T00:00:00Z
source:        TCI
`

	result, err := p.Parse(response, "example.ru")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	pd := result.Domain

	if pd.DomainName != "example.ru" {
		t.Errorf("DomainName = %q, want example.ru", pd.DomainName)
	}

	if len(pd.Nameservers) != 2 {
		t.Errorf("len(Nameservers) = %d, want 2", len(pd.Nameservers))
	} else if pd.Nameservers[0] != "ns1.example.ru" {
		t.Errorf("Nameservers[0] = %q, want ns1.example.ru", pd.Nameservers[0])
	}

	// TCINET uses comma-separated states
	if len(pd.Status) != 3 {
		t.Errorf("len(Status) = %d, want 3, got %v", len(pd.Status), pd.Status)
	}

	if pd.CreatedDate == nil {
		t.Error("CreatedDate should not be nil")
	} else if pd.CreatedDate.Year() != 2000 {
		t.Errorf("CreatedDate.Year() = %d, want 2000", pd.CreatedDate.Year())
	}

	if pd.ExpirationDate == nil {
		t.Error("ExpirationDate should not be nil")
	} else if pd.ExpirationDate.Year() != 2025 {
		t.Errorf("ExpirationDate.Year() = %d, want 2025", pd.ExpirationDate.Year())
	}

	if pd.Registrar == nil {
		t.Error("Registrar should not be nil")
	} else if pd.Registrar.Name != "REGISTRAR-RU" {
		t.Errorf("Registrar.Name = %q, want REGISTRAR-RU", pd.Registrar.Name)
	}

	if pd.Registrant == nil {
		t.Fatal("Registrant should not be nil")
	}
	if pd.Registrant.Organization != "Example Organization LLC" {
		t.Errorf("Registrant.Organization = %q, want Example Organization LLC", pd.Registrant.Organization)
	}

	if result.Confidence != "high" {
		t.Errorf("Confidence = %q, want high", result.Confidence)
	}

	if result.ParserName != "ru" {
		t.Errorf("ParserName = %q, want ru", result.ParserName)
	}
}

func TestRUParser_Parse_WithPerson(t *testing.T) {
	p := NewRUParser()

	response := `domain:        EXAMPLE.RU
nserver:       ns1.example.ru.
state:         REGISTERED, DELEGATED
person:        Private Person
e-mail:        person@example.ru
phone:         +7.4951234567
registrar:     REGISTRAR-RU
created:       2010-05-20T00:00:00Z
paid-till:     2025-05-20T00:00:00Z
source:        TCI
`

	result, err := p.Parse(response, "example.ru")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	pd := result.Domain

	if pd.Registrant == nil {
		t.Fatal("Registrant should not be nil")
	}
	if pd.Registrant.Name != "Private Person" {
		t.Errorf("Registrant.Name = %q, want Private Person", pd.Registrant.Name)
	}
	if pd.Registrant.Email != "person@example.ru" {
		t.Errorf("Registrant.Email = %q, want person@example.ru", pd.Registrant.Email)
	}
	if pd.Registrant.Phone != "+7.4951234567" {
		t.Errorf("Registrant.Phone = %q, want +7.4951234567", pd.Registrant.Phone)
	}
}

func TestRUParser_Parse_NotFound(t *testing.T) {
	p := NewRUParser()

	tests := []struct {
		name     string
		response string
	}{
		{"No entries found", "No entries found for the selected source(s).\n"},
		{"No object found", "% No object found\n"},
		{"Object not found", "Object not found\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := p.Parse(tt.response, "notfound.ru")
			if err != nil {
				t.Fatalf("Parse error = %v", err)
			}

			if result.Confidence != "low" {
				t.Errorf("Confidence = %q, want low", result.Confidence)
			}

			if len(result.Errors) == 0 {
				t.Error("Expected errors to be populated")
			}
		})
	}
}

func TestRUParser_Parse_EmptyResponse(t *testing.T) {
	p := NewRUParser()

	result, err := p.Parse("", "example.ru")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	if result.Domain.DomainName != "example.ru" {
		t.Errorf("DomainName = %q, want example.ru", result.Domain.DomainName)
	}
}

func TestRUParser_Parse_CommentLines(t *testing.T) {
	p := NewRUParser()

	response := `% By querying this database, you agree to abide by
% the following policy
% https://www.tcinet.ru/whois-terms

domain:        EXAMPLE.RU
state:         REGISTERED, DELEGATED
registrar:     REGISTRAR-RU
`

	result, err := p.Parse(response, "example.ru")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	if result.Domain.DomainName != "example.ru" {
		t.Errorf("DomainName = %q, want example.ru", result.Domain.DomainName)
	}

	if result.Domain.Registrar == nil {
		t.Error("Registrar should not be nil")
	}
}

func TestParseRUDate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantYear int
		wantNil  bool
	}{
		{"RFC3339", "2024-01-15T10:30:00Z", 2024, false},
		{"ISO without Z", "2024-01-15T10:30:00", 2024, false},
		{"Date only", "2024-01-15", 2024, false},
		{"Dot format", "2024.01.15", 2024, false},
		{"Empty string", "", 0, true},
		{"Invalid", "not a date", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseRUDate(tt.input)
			if tt.wantNil {
				if result != nil {
					t.Errorf("parseRUDate(%q) = %v, want nil", tt.input, result)
				}
			} else {
				if result == nil {
					t.Errorf("parseRUDate(%q) = nil, want year %d", tt.input, tt.wantYear)
				} else if result.Year() != tt.wantYear {
					t.Errorf("parseRUDate(%q).Year() = %d, want %d", tt.input, result.Year(), tt.wantYear)
				}
			}
		})
	}
}

func TestNormalizeRUNameserver(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ns1.example.ru", "ns1.example.ru"},
		{"NS1.EXAMPLE.RU", "ns1.example.ru"},
		{"ns1.example.ru.", "ns1.example.ru"},
		{"  ns1.example.ru  ", "ns1.example.ru"},
		{"ns1.example.ru 192.168.1.1", "ns1.example.ru"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeRUNameserver(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeRUNameserver(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestRUParser_Parse_RealWorldFormat(t *testing.T) {
	p := NewRUParser()

	// Simulated real-world TCINET response format
	response := `% By querying this database, you agree to abide by
% the following policy
% https://www.tcinet.ru/content/document/42

domain:        YANDEX.RU
nserver:       ns1.yandex.ru.
nserver:       ns2.yandex.ru.
nserver:       ns9.z5h64q92x9.net.
state:         REGISTERED, DELEGATED, VERIFIED
org:           YANDEX LLC
registrar:     RU-CENTER-RU
admin-contact: https://www.nic.ru/whois
created:       1997-09-23T09:45:07Z
paid-till:     2025-09-30T21:00:00Z
free-date:     2025-11-01
source:        TCI

Last updated on 2024-01-15T10:30:00Z
`

	result, err := p.Parse(response, "yandex.ru")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	pd := result.Domain

	if pd.DomainName != "yandex.ru" {
		t.Errorf("DomainName = %q, want yandex.ru", pd.DomainName)
	}

	if len(pd.Nameservers) != 3 {
		t.Errorf("len(Nameservers) = %d, want 3", len(pd.Nameservers))
	}

	if pd.Registrant.Organization != "YANDEX LLC" {
		t.Errorf("Registrant.Organization = %q, want YANDEX LLC", pd.Registrant.Organization)
	}

	if pd.CreatedDate == nil || pd.CreatedDate.Year() != 1997 {
		t.Errorf("CreatedDate = %v, want 1997", pd.CreatedDate)
	}
}

func BenchmarkRUParser_Parse(b *testing.B) {
	p := NewRUParser()

	response := `domain:        EXAMPLE.RU
nserver:       ns1.example.ru.
nserver:       ns2.example.ru.
state:         REGISTERED, DELEGATED, VERIFIED
org:           Example Organization
registrar:     REGISTRAR-RU
created:       2000-01-15T00:00:00Z
paid-till:     2025-01-15T00:00:00Z
source:        TCI
`

	b.ResetTimer()
	for b.Loop() {
		_, _ = p.Parse(response, "example.ru")
	}
}
