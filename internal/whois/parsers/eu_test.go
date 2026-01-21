package parsers

import (
	"testing"
)

func TestEUParser_Name(t *testing.T) {
	p := NewEUParser()
	if p.Name() != "eu" {
		t.Errorf("Name() = %q, want eu", p.Name())
	}
}

func TestEUParser_SupportsTLD(t *testing.T) {
	p := NewEUParser()

	tests := []struct {
		tld      string
		expected bool
	}{
		{"eu", true},
		{"EU", true},
		{"Eu", true},
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

func TestEUParser_Parse_BasicDomain(t *testing.T) {
	p := NewEUParser()

	response := `Domain: example.eu
Script: LATIN

Registrant:
        NOT DISCLOSED!
        Visit www.eurid.eu for webbased whois.

Technical:
        Name: Technical Contact
        Organisation: Example Tech Ltd
        Language: en
        Phone: +32.123456789
        Email: tech@example.eu

Registrar:
        Name: Example Registrar
        Website: https://www.example-registrar.eu

Name servers:
        ns1.example.eu
        ns2.example.eu

DNSSEC:
        signedDelegation

Please visit www.eurid.eu for more info.
`

	result, err := p.Parse(response, "example.eu")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	pd := result.Domain

	if pd.DomainName != "example.eu" {
		t.Errorf("DomainName = %q, want example.eu", pd.DomainName)
	}

	if len(pd.Nameservers) != 2 {
		t.Errorf("len(Nameservers) = %d, want 2", len(pd.Nameservers))
	} else if pd.Nameservers[0] != "ns1.example.eu" {
		t.Errorf("Nameservers[0] = %q, want ns1.example.eu", pd.Nameservers[0])
	}

	if pd.TechContact == nil {
		t.Fatal("TechContact should not be nil")
	}
	if pd.TechContact.Name != "Technical Contact" {
		t.Errorf("TechContact.Name = %q, want Technical Contact", pd.TechContact.Name)
	}

	if pd.Registrar == nil {
		t.Fatal("Registrar should not be nil")
	}
	if pd.Registrar.Name != "Example Registrar" {
		t.Errorf("Registrar.Name = %q, want Example Registrar", pd.Registrar.Name)
	}

	if pd.DNSSECSigned == nil || !*pd.DNSSECSigned {
		t.Error("DNSSECSigned should be true")
	}

	if result.Confidence != "high" {
		t.Errorf("Confidence = %q, want high", result.Confidence)
	}
}

func TestEUParser_Parse_NotFound(t *testing.T) {
	p := NewEUParser()

	tests := []struct {
		name     string
		response string
	}{
		{"Status available", "Status: AVAILABLE\n"},
		{"Not found", "Domain not found\n"},
		{"No entries", "No entries found\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := p.Parse(tt.response, "notfound.eu")
			if err != nil {
				t.Fatalf("Parse error = %v", err)
			}

			if result.Confidence != "low" {
				t.Errorf("Confidence = %q, want low", result.Confidence)
			}
		})
	}
}

func TestEUParser_Parse_EmptyResponse(t *testing.T) {
	p := NewEUParser()

	result, err := p.Parse("", "example.eu")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	if result.Domain.DomainName != "example.eu" {
		t.Errorf("DomainName = %q, want example.eu", result.Domain.DomainName)
	}
}

func TestParseEUDate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantYear int
		wantNil  bool
	}{
		{"RFC3339", "2024-01-15T10:30:00Z", 2024, false},
		{"Date only", "2024-01-15", 2024, false},
		{"European format", "15.01.2024", 2024, false},
		{"Empty string", "", 0, true},
		{"Invalid", "not a date", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseEUDate(tt.input)
			if tt.wantNil {
				if result != nil {
					t.Errorf("parseEUDate(%q) = %v, want nil", tt.input, result)
				}
			} else {
				if result == nil {
					t.Errorf("parseEUDate(%q) = nil, want year %d", tt.input, tt.wantYear)
				} else if result.Year() != tt.wantYear {
					t.Errorf("parseEUDate(%q).Year() = %d, want %d", tt.input, result.Year(), tt.wantYear)
				}
			}
		})
	}
}

func TestNormalizeEUNameserver(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ns1.example.eu", "ns1.example.eu"},
		{"NS1.EXAMPLE.EU", "ns1.example.eu"},
		{"ns1.example.eu.", "ns1.example.eu"},
		{"keyTag:12345 flags:257", ""}, // DNSSEC key, not nameserver
		{"example", ""},                // No dot
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeEUNameserver(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeEUNameserver(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func BenchmarkEUParser_Parse(b *testing.B) {
	p := NewEUParser()

	response := `Domain: example.eu
Script: LATIN
Technical:
        Name: Technical Contact
        Organisation: Example Tech Ltd
Registrar:
        Name: Example Registrar
Name servers:
        ns1.example.eu
        ns2.example.eu
DNSSEC:
        signedDelegation
`

	b.ResetTimer()
	for b.Loop() {
		_, _ = p.Parse(response, "example.eu")
	}
}
