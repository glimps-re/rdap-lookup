package parsers

import (
	"testing"
)

func TestITParser_Name(t *testing.T) {
	p := NewITParser()
	if p.Name() != "it" {
		t.Errorf("Name() = %q, want it", p.Name())
	}
}

func TestITParser_SupportsTLD(t *testing.T) {
	p := NewITParser()

	tests := []struct {
		tld      string
		expected bool
	}{
		{"it", true},
		{"IT", true},
		{"It", true},
		{"com", false},
		{"de", false},
	}

	for _, tt := range tests {
		t.Run(tt.tld, func(t *testing.T) {
			if got := p.SupportsTLD(tt.tld); got != tt.expected {
				t.Errorf("SupportsTLD(%q) = %v, want %v", tt.tld, got, tt.expected)
			}
		})
	}
}

func TestITParser_Parse_BasicDomain(t *testing.T) {
	p := NewITParser()

	response := `*********************************************************************
* Please note that the following result could be a subgroup of      *
* the data contained in the database.                               *
*********************************************************************

Domain:             example.it
Status:             ok

Created:            2000-01-15 00:00:00
Last Update:        2024-01-15 10:30:00
Expire Date:        2025-01-15

Registrant
  Organization:     Example S.r.l.

Admin Contact
  Name:             Admin Contact Name
  Organization:     Example S.r.l.

Technical Contacts
  Name:             Technical Contact Name
  Organization:     Example Hosting S.r.l.

Registrar
  Organization:     Example Registrar S.r.l.
  Name:             EXAMPLE-REG
  Web:              https://www.example-registrar.it

Nameservers
  ns1.example.it
  ns2.example.it
`

	result, err := p.Parse(response, "example.it")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	pd := result.Domain

	if pd.DomainName != "example.it" {
		t.Errorf("DomainName = %q, want example.it", pd.DomainName)
	}

	if len(pd.Status) != 1 || pd.Status[0] != "ok" {
		t.Errorf("Status = %v, want [ok]", pd.Status)
	}

	if pd.CreatedDate == nil || pd.CreatedDate.Year() != 2000 {
		t.Errorf("CreatedDate = %v, want year 2000", pd.CreatedDate)
	}

	if pd.UpdatedDate == nil || pd.UpdatedDate.Year() != 2024 {
		t.Errorf("UpdatedDate = %v, want year 2024", pd.UpdatedDate)
	}

	if pd.ExpirationDate == nil || pd.ExpirationDate.Year() != 2025 {
		t.Errorf("ExpirationDate = %v, want year 2025", pd.ExpirationDate)
	}

	if len(pd.Nameservers) != 2 {
		t.Errorf("len(Nameservers) = %d, want 2", len(pd.Nameservers))
	}

	if pd.Registrant == nil || pd.Registrant.Organization != "Example S.r.l." {
		t.Errorf("Registrant.Organization = %v, want Example S.r.l.", pd.Registrant)
	}

	if pd.AdminContact == nil || pd.AdminContact.Name != "Admin Contact Name" {
		t.Errorf("AdminContact.Name = %v, want Admin Contact Name", pd.AdminContact)
	}

	if pd.TechContact == nil || pd.TechContact.Name != "Technical Contact Name" {
		t.Errorf("TechContact.Name = %v, want Technical Contact Name", pd.TechContact)
	}

	if pd.Registrar == nil || pd.Registrar.Organization != "Example Registrar S.r.l." {
		t.Errorf("Registrar.Organization = %v, want Example Registrar S.r.l.", pd.Registrar)
	}

	if result.Confidence != "high" {
		t.Errorf("Confidence = %q, want high", result.Confidence)
	}
}

func TestITParser_Parse_NotFound(t *testing.T) {
	p := NewITParser()

	tests := []struct {
		name     string
		response string
	}{
		{"Status available", "Status:             AVAILABLE\n"},
		{"Object not found", "Object not found\n"},
		{"No entries", "No entries found\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := p.Parse(tt.response, "notfound.it")
			if err != nil {
				t.Fatalf("Parse error = %v", err)
			}

			if result.Confidence != "low" {
				t.Errorf("Confidence = %q, want low", result.Confidence)
			}
		})
	}
}

func TestITParser_Parse_EmptyResponse(t *testing.T) {
	p := NewITParser()

	result, err := p.Parse("", "example.it")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	if result.Domain.DomainName != "example.it" {
		t.Errorf("DomainName = %q, want example.it", result.Domain.DomainName)
	}
}

func TestParseITDate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantYear int
		wantNil  bool
	}{
		{"NIC.it format", "2024-01-15 10:30:00", 2024, false},
		{"Date only", "2024-01-15", 2024, false},
		{"RFC3339", "2024-01-15T10:30:00Z", 2024, false},
		{"Empty string", "", 0, true},
		{"Invalid", "not a date", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseITDate(tt.input)
			if tt.wantNil {
				if result != nil {
					t.Errorf("parseITDate(%q) = %v, want nil", tt.input, result)
				}
			} else {
				if result == nil {
					t.Errorf("parseITDate(%q) = nil, want year %d", tt.input, tt.wantYear)
				} else if result.Year() != tt.wantYear {
					t.Errorf("parseITDate(%q).Year() = %d, want %d", tt.input, result.Year(), tt.wantYear)
				}
			}
		})
	}
}

func TestNormalizeITNameserver(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ns1.example.it", "ns1.example.it"},
		{"NS1.EXAMPLE.IT", "ns1.example.it"},
		{"ns1.example.it.", "ns1.example.it"},
		{"example", ""}, // No dot
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeITNameserver(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeITNameserver(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func BenchmarkITParser_Parse(b *testing.B) {
	p := NewITParser()

	response := `Domain:             example.it
Status:             ok
Created:            2000-01-15 00:00:00
Last Update:        2024-01-15 10:30:00
Expire Date:        2025-01-15
Registrant
  Organization:     Example S.r.l.
Registrar
  Organization:     Example Registrar S.r.l.
Nameservers
  ns1.example.it
  ns2.example.it
`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = p.Parse(response, "example.it")
	}
}
