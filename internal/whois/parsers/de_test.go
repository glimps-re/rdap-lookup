package parsers

import (
	"testing"
)

func TestDEParser_Name(t *testing.T) {
	p := NewDEParser()
	if p.Name() != "de" {
		t.Errorf("Name() = %q, want de", p.Name())
	}
}

func TestDEParser_SupportsTLD(t *testing.T) {
	p := NewDEParser()

	tests := []struct {
		tld      string
		expected bool
	}{
		{"de", true},
		{"DE", true},
		{"De", true},
		{"com", false},
		{"de.com", false},
		{"net", false},
	}

	for _, tt := range tests {
		t.Run(tt.tld, func(t *testing.T) {
			if got := p.SupportsTLD(tt.tld); got != tt.expected {
				t.Errorf("SupportsTLD(%q) = %v, want %v", tt.tld, got, tt.expected)
			}
		})
	}
}

func TestDEParser_Parse_BasicDomain(t *testing.T) {
	p := NewDEParser()

	response := `Domain: example.de
Nserver: ns1.example.de
Nserver: ns2.example.de
Status: connect
Changed: 2024-01-15T10:30:00+01:00
RegCreatedDate: 2000-05-20T00:00:00+02:00
`

	result, err := p.Parse(response, "example.de")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	pd := result.Domain

	if pd.DomainName != "example.de" {
		t.Errorf("DomainName = %q, want example.de", pd.DomainName)
	}

	if len(pd.Nameservers) != 2 {
		t.Errorf("len(Nameservers) = %d, want 2", len(pd.Nameservers))
	} else if pd.Nameservers[0] != "ns1.example.de" {
		t.Errorf("Nameservers[0] = %q, want ns1.example.de", pd.Nameservers[0])
	}

	if len(pd.Status) != 1 || pd.Status[0] != "connect" {
		t.Errorf("Status = %v, want [connect]", pd.Status)
	}

	if pd.UpdatedDate == nil {
		t.Error("UpdatedDate should not be nil")
	} else if pd.UpdatedDate.Year() != 2024 {
		t.Errorf("UpdatedDate.Year() = %d, want 2024", pd.UpdatedDate.Year())
	}

	if pd.CreatedDate == nil {
		t.Error("CreatedDate should not be nil")
	} else if pd.CreatedDate.Year() != 2000 {
		t.Errorf("CreatedDate.Year() = %d, want 2000", pd.CreatedDate.Year())
	}

	if result.Confidence != "high" {
		t.Errorf("Confidence = %q, want high", result.Confidence)
	}

	if result.ParserName != "de" {
		t.Errorf("ParserName = %q, want de", result.ParserName)
	}
}

func TestDEParser_Parse_WithContacts(t *testing.T) {
	p := NewDEParser()

	response := `Domain: example.de
Nserver: ns1.example.de
Status: connect

[Holder]
Type: PERSON
Name: John Doe
Organisation: Example GmbH
Address: Example Street 123
City: Berlin
PostalCode: 10115
CountryCode: DE
Email: holder@example.de
Phone: +49.301234567

[Tech-C]
Type: ROLE
Name: Technical Support
Organisation: Hosting Provider
Email: tech@provider.de
`

	result, err := p.Parse(response, "example.de")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	pd := result.Domain

	// Check registrant (Holder)
	if pd.Registrant == nil {
		t.Fatal("Registrant should not be nil")
	}
	if pd.Registrant.Name != "John Doe" {
		t.Errorf("Registrant.Name = %q, want John Doe", pd.Registrant.Name)
	}
	if pd.Registrant.Organization != "Example GmbH" {
		t.Errorf("Registrant.Organization = %q, want Example GmbH", pd.Registrant.Organization)
	}
	if pd.Registrant.City != "Berlin" {
		t.Errorf("Registrant.City = %q, want Berlin", pd.Registrant.City)
	}
	if pd.Registrant.Country != "DE" {
		t.Errorf("Registrant.Country = %q, want DE", pd.Registrant.Country)
	}

	// Check tech contact
	if pd.TechContact == nil {
		t.Fatal("TechContact should not be nil")
	}
	if pd.TechContact.Name != "Technical Support" {
		t.Errorf("TechContact.Name = %q, want Technical Support", pd.TechContact.Name)
	}
}

func TestDEParser_Parse_NotFound(t *testing.T) {
	p := NewDEParser()

	tests := []struct {
		name     string
		response string
	}{
		{"Status free", "Status: free\n"},
		{"Object not found", "% Object not found\n"},
		{"No entries found", "No entries found for the selected source(s).\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := p.Parse(tt.response, "notfound.de")
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

func TestDEParser_Parse_DNSSEC(t *testing.T) {
	p := NewDEParser()

	tests := []struct {
		name     string
		response string
		expected bool
	}{
		{
			name:     "DNSKEY present",
			response: "Domain: example.de\nDnskey: 257 3 8 AwEAAb...\n",
			expected: true,
		},
		{
			name:     "DNSSEC signed",
			response: "Domain: example.de\nDnssec: Y\n",
			expected: true,
		},
		{
			name:     "DNSSEC unsigned",
			response: "Domain: example.de\nDnssec: N\n",
			expected: false,
		},
		{
			name:     "DNSSEC unsigned explicit",
			response: "Domain: example.de\nDnssec: unsigned\n",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := p.Parse(tt.response, "example.de")
			if err != nil {
				t.Fatalf("Parse error = %v", err)
			}

			if result.Domain.DNSSECSigned == nil {
				t.Fatal("DNSSECSigned should not be nil")
			}

			if *result.Domain.DNSSECSigned != tt.expected {
				t.Errorf("DNSSECSigned = %v, want %v", *result.Domain.DNSSECSigned, tt.expected)
			}
		})
	}
}

func TestDEParser_Parse_NameserverWithIP(t *testing.T) {
	p := NewDEParser()

	response := `Domain: example.de
Nserver: ns1.example.de 192.168.1.1
Nserver: ns2.example.de 192.168.1.2
`

	result, err := p.Parse(response, "example.de")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	if len(result.Domain.Nameservers) != 2 {
		t.Fatalf("len(Nameservers) = %d, want 2", len(result.Domain.Nameservers))
	}

	// IP addresses should be stripped
	if result.Domain.Nameservers[0] != "ns1.example.de" {
		t.Errorf("Nameservers[0] = %q, want ns1.example.de", result.Domain.Nameservers[0])
	}
}

func TestParseDEDate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantYear int
		wantNil  bool
	}{
		{"RFC3339", "2024-01-15T10:30:00Z", 2024, false},
		{"With timezone offset", "2024-01-15T10:30:00+01:00", 2024, false},
		{"Date only", "2024-01-15", 2024, false},
		{"Date with time", "2024-01-15 10:30:00", 2024, false},
		{"ISO without Z", "2024-01-15T10:30:00", 2024, false},
		{"Empty string", "", 0, true},
		{"Invalid", "not a date", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseDEDate(tt.input)
			if tt.wantNil {
				if result != nil {
					t.Errorf("parseDEDate(%q) = %v, want nil", tt.input, result)
				}
			} else {
				if result == nil {
					t.Errorf("parseDEDate(%q) = nil, want year %d", tt.input, tt.wantYear)
				} else if result.Year() != tt.wantYear {
					t.Errorf("parseDEDate(%q).Year() = %d, want %d", tt.input, result.Year(), tt.wantYear)
				}
			}
		})
	}
}

func TestNormalizeNameserver(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ns1.example.de", "ns1.example.de"},
		{"NS1.EXAMPLE.DE", "ns1.example.de"},
		{"ns1.example.de.", "ns1.example.de"},
		{"  ns1.example.de  ", "ns1.example.de"},
		{"ns1.example.de 192.168.1.1", "ns1.example.de"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeNameserver(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeNameserver(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestDEParser_Parse_EmptyResponse(t *testing.T) {
	p := NewDEParser()

	result, err := p.Parse("", "example.de")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	// Should use domain as fallback
	if result.Domain.DomainName != "example.de" {
		t.Errorf("DomainName = %q, want example.de", result.Domain.DomainName)
	}
}

func TestDEParser_Parse_RealWorldFormat(t *testing.T) {
	p := NewDEParser()

	// Simulated real-world DENIC response format
	response := `% Restricted rights.
%
% Terms and Conditions of Use
%
% The above data may only be used within the scope of technical or
% administrative necessities of Internet operation or to remedy legal
% problems.

Domain: google.de
Nserver: ns1.google.com
Nserver: ns2.google.com
Nserver: ns3.google.com
Nserver: ns4.google.com
Status: connect
Changed: 2023-09-15T08:25:21+02:00

[Tech-C]
Type: ROLE
Name: DNS Admin
Organisation: Google Germany GmbH
Address: ABC-Strasse 19
PostalCode: 20354
City: Hamburg
CountryCode: DE
Phone: +49.40808179000
Fax: +49.40808179001
Email: dns-admin@google.com
Changed: 2015-11-19T14:52:42+01:00
`

	result, err := p.Parse(response, "google.de")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	pd := result.Domain

	if pd.DomainName != "google.de" {
		t.Errorf("DomainName = %q, want google.de", pd.DomainName)
	}

	if len(pd.Nameservers) != 4 {
		t.Errorf("len(Nameservers) = %d, want 4", len(pd.Nameservers))
	}

	if pd.TechContact == nil {
		t.Fatal("TechContact should not be nil")
	}

	if pd.TechContact.Name != "DNS Admin" {
		t.Errorf("TechContact.Name = %q, want DNS Admin", pd.TechContact.Name)
	}

	if pd.TechContact.Organization != "Google Germany GmbH" {
		t.Errorf("TechContact.Organization = %q, want Google Germany GmbH", pd.TechContact.Organization)
	}
}

func BenchmarkDEParser_Parse(b *testing.B) {
	p := NewDEParser()

	response := `Domain: example.de
Nserver: ns1.example.de
Nserver: ns2.example.de
Status: connect
Changed: 2024-01-15T10:30:00+01:00

[Holder]
Type: PERSON
Name: John Doe
Organisation: Example GmbH
`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = p.Parse(response, "example.de")
	}
}
