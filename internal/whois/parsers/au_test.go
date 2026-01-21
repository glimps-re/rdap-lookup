package parsers

import (
	"testing"
)

func TestAUParser_Name(t *testing.T) {
	p := NewAUParser()
	if p.Name() != "au" {
		t.Errorf("Name() = %q, want au", p.Name())
	}
}

func TestAUParser_SupportsTLD(t *testing.T) {
	p := NewAUParser()

	tests := []struct {
		tld      string
		expected bool
	}{
		{"au", true},
		{"AU", true},
		{"com.au", true},
		{"net.au", true},
		{"org.au", true},
		{"edu.au", true},
		{"gov.au", true},
		{"asn.au", true},
		{"id.au", true},
		{"com", false},
		{"de", false},
		{"australia", false},
	}

	for _, tt := range tests {
		t.Run(tt.tld, func(t *testing.T) {
			if got := p.SupportsTLD(tt.tld); got != tt.expected {
				t.Errorf("SupportsTLD(%q) = %v, want %v", tt.tld, got, tt.expected)
			}
		})
	}
}

func TestAUParser_Parse_BasicDomain(t *testing.T) {
	p := NewAUParser()

	response := `Domain Name: example.com.au
Registry Domain ID: D12345678-AU
Registrar: Example Registrar Pty Ltd
Status: ok
Registrant Contact ID: ABC123
Registrant Contact Name: Example Company Pty Ltd
Tech Contact ID: XYZ789
Tech Contact Name: Technical Support
Name Server: ns1.example.com.au
Name Server: ns2.example.com.au
DNSSEC: unsigned
Last Modified: 2024-01-15T10:30:00Z
`

	result, err := p.Parse(response, "example.com.au")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	pd := result.Domain

	if pd.DomainName != "example.com.au" {
		t.Errorf("DomainName = %q, want example.com.au", pd.DomainName)
	}

	if pd.RegistryDomainID != "D12345678-AU" {
		t.Errorf("RegistryDomainID = %q, want D12345678-AU", pd.RegistryDomainID)
	}

	if len(pd.Status) != 1 || pd.Status[0] != "ok" {
		t.Errorf("Status = %v, want [ok]", pd.Status)
	}

	if len(pd.Nameservers) != 2 {
		t.Errorf("len(Nameservers) = %d, want 2", len(pd.Nameservers))
	}

	if pd.UpdatedDate == nil {
		t.Error("UpdatedDate should not be nil")
	} else if pd.UpdatedDate.Year() != 2024 {
		t.Errorf("UpdatedDate.Year() = %d, want 2024", pd.UpdatedDate.Year())
	}

	if pd.Registrar == nil {
		t.Error("Registrar should not be nil")
	} else if pd.Registrar.Name != "Example Registrar Pty Ltd" {
		t.Errorf("Registrar.Name = %q, want Example Registrar Pty Ltd", pd.Registrar.Name)
	}

	if pd.Registrant == nil {
		t.Fatal("Registrant should not be nil")
	}
	if pd.Registrant.Name != "Example Company Pty Ltd" {
		t.Errorf("Registrant.Name = %q, want Example Company Pty Ltd", pd.Registrant.Name)
	}
	if pd.Registrant.Handle != "ABC123" {
		t.Errorf("Registrant.Handle = %q, want ABC123", pd.Registrant.Handle)
	}

	if pd.TechContact == nil {
		t.Fatal("TechContact should not be nil")
	}
	if pd.TechContact.Name != "Technical Support" {
		t.Errorf("TechContact.Name = %q, want Technical Support", pd.TechContact.Name)
	}

	if result.Confidence != "high" {
		t.Errorf("Confidence = %q, want high", result.Confidence)
	}

	if result.ParserName != "au" {
		t.Errorf("ParserName = %q, want au", result.ParserName)
	}
}

func TestAUParser_Parse_WithDates(t *testing.T) {
	p := NewAUParser()

	response := `Domain Name: example.com.au
Status: ok
Creation Date: 2000-05-20T00:00:00Z
Last Modified: 2024-01-15T10:30:00Z
Registry Expiry Date: 2025-05-20T00:00:00Z
`

	result, err := p.Parse(response, "example.com.au")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	pd := result.Domain

	if pd.CreatedDate == nil {
		t.Error("CreatedDate should not be nil")
	} else if pd.CreatedDate.Year() != 2000 {
		t.Errorf("CreatedDate.Year() = %d, want 2000", pd.CreatedDate.Year())
	}

	if pd.UpdatedDate == nil {
		t.Error("UpdatedDate should not be nil")
	} else if pd.UpdatedDate.Year() != 2024 {
		t.Errorf("UpdatedDate.Year() = %d, want 2024", pd.UpdatedDate.Year())
	}

	if pd.ExpirationDate == nil {
		t.Error("ExpirationDate should not be nil")
	} else if pd.ExpirationDate.Year() != 2025 {
		t.Errorf("ExpirationDate.Year() = %d, want 2025", pd.ExpirationDate.Year())
	}
}

func TestAUParser_Parse_NotFound(t *testing.T) {
	p := NewAUParser()

	tests := []struct {
		name     string
		response string
	}{
		{"No Data Found", "No Data Found\n"},
		{"Not found", "Domain not found\n"},
		{"No entries", "No entries found\n"},
		{"No match", "No match for domain\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := p.Parse(tt.response, "notfound.com.au")
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

func TestAUParser_Parse_DNSSEC(t *testing.T) {
	p := NewAUParser()

	tests := []struct {
		name     string
		response string
		expected bool
	}{
		{
			name:     "DNSSEC signed",
			response: "Domain Name: example.com.au\nDNSSEC: signedDelegation\n",
			expected: true,
		},
		{
			name:     "DNSSEC unsigned",
			response: "Domain Name: example.com.au\nDNSSEC: unsigned\n",
			expected: false,
		},
		{
			name:     "DNSSEC no",
			response: "Domain Name: example.com.au\nDNSSEC: no\n",
			expected: false,
		},
		{
			name:     "DNSSEC N",
			response: "Domain Name: example.com.au\nDNSSEC: N\n",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := p.Parse(tt.response, "example.com.au")
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

func TestAUParser_Parse_StatusWithURLs(t *testing.T) {
	p := NewAUParser()

	response := `Domain Name: example.com.au
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
`

	result, err := p.Parse(response, "example.com.au")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	// URLs should be stripped from status
	for _, status := range result.Domain.Status {
		if status == "" || status[0:4] == "http" {
			t.Errorf("Status should not contain URLs or be empty: %q", status)
		}
	}
}

func TestAUParser_Parse_EmptyResponse(t *testing.T) {
	p := NewAUParser()

	result, err := p.Parse("", "example.com.au")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	if result.Domain.DomainName != "example.com.au" {
		t.Errorf("DomainName = %q, want example.com.au", result.Domain.DomainName)
	}
}

func TestAUParser_Parse_CommentLines(t *testing.T) {
	p := NewAUParser()

	response := `% WHOIS data for .au domains
% Rate limit exceeded
# Comment line
Domain Name: example.com.au
Status: ok
`

	result, err := p.Parse(response, "example.com.au")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	if result.Domain.DomainName != "example.com.au" {
		t.Errorf("DomainName = %q, want example.com.au", result.Domain.DomainName)
	}
}

func TestParseAUDate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantYear int
		wantNil  bool
	}{
		{"RFC3339", "2024-01-15T10:30:00Z", 2024, false},
		{"With timezone", "2024-01-15T10:30:00+10:00", 2024, false},
		{"ISO without Z", "2024-01-15T10:30:00", 2024, false},
		{"Date only", "2024-01-15", 2024, false},
		{"Date with time", "2024-01-15 10:30:00", 2024, false},
		{"With timezone abbrev", "2024-01-15T10:30:00Z (AEST)", 2024, false},
		{"Day-Month-Year", "02-Jan-2006", 2006, false},
		{"Day Month Year", "02 Jan 2006", 2006, false},
		{"Empty string", "", 0, true},
		{"Invalid", "not a date", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseAUDate(tt.input)
			if tt.wantNil {
				if result != nil {
					t.Errorf("parseAUDate(%q) = %v, want nil", tt.input, result)
				}
			} else {
				if result == nil {
					t.Errorf("parseAUDate(%q) = nil, want year %d", tt.input, tt.wantYear)
				} else if result.Year() != tt.wantYear {
					t.Errorf("parseAUDate(%q).Year() = %d, want %d", tt.input, result.Year(), tt.wantYear)
				}
			}
		})
	}
}

func TestNormalizeAUNameserver(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ns1.example.com.au", "ns1.example.com.au"},
		{"NS1.EXAMPLE.COM.AU", "ns1.example.com.au"},
		{"ns1.example.com.au.", "ns1.example.com.au"},
		{"  ns1.example.com.au  ", "ns1.example.com.au"},
		{"ns1.example.com.au 192.168.1.1", "ns1.example.com.au"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeAUNameserver(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeAUNameserver(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestAUParser_Parse_RealWorldFormat(t *testing.T) {
	p := NewAUParser()

	// Simulated real-world auDA response format
	response := `Domain Name: google.com.au
Registry Domain ID: D12345678-AU
Registrar WHOIS Server: whois.auda.org.au
Registrar URL: http://www.markmonitor.com
Last Modified: 2023-12-15T10:30:00Z
Registrar: MarkMonitor Inc.
Registrar Abuse Contact Email: abusecomplaints@markmonitor.com
Registrar Abuse Contact Phone: +1.2083895740
Status: clientDeleteProhibited
Status: clientTransferProhibited
Status: clientUpdateProhibited
Registrant Contact ID: GOOG123
Registrant Contact Name: Domain Administrator
Tech Contact ID: TECH456
Tech Contact Name: Technical Support
Name Server: ns1.google.com
Name Server: ns2.google.com
Name Server: ns3.google.com
Name Server: ns4.google.com
DNSSEC: unsigned
`

	result, err := p.Parse(response, "google.com.au")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	pd := result.Domain

	if pd.DomainName != "google.com.au" {
		t.Errorf("DomainName = %q, want google.com.au", pd.DomainName)
	}

	if len(pd.Status) != 3 {
		t.Errorf("len(Status) = %d, want 3", len(pd.Status))
	}

	if len(pd.Nameservers) != 4 {
		t.Errorf("len(Nameservers) = %d, want 4", len(pd.Nameservers))
	}

	if pd.Registrar == nil {
		t.Fatal("Registrar should not be nil")
	}
	if pd.Registrar.Name != "MarkMonitor Inc." {
		t.Errorf("Registrar.Name = %q, want MarkMonitor Inc.", pd.Registrar.Name)
	}
	if pd.Registrar.Email != "abusecomplaints@markmonitor.com" {
		t.Errorf("Registrar.Email = %q, want abusecomplaints@markmonitor.com", pd.Registrar.Email)
	}

	if pd.Registrant.Name != "Domain Administrator" {
		t.Errorf("Registrant.Name = %q, want Domain Administrator", pd.Registrant.Name)
	}
}

func TestAUParser_Parse_AdminContact(t *testing.T) {
	p := NewAUParser()

	response := `Domain Name: example.com.au
Admin Contact ID: ADM001
Admin Contact Name: Admin Person
`

	result, err := p.Parse(response, "example.com.au")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	if result.Domain.AdminContact == nil {
		t.Fatal("AdminContact should not be nil")
	}
	if result.Domain.AdminContact.Handle != "ADM001" {
		t.Errorf("AdminContact.Handle = %q, want ADM001", result.Domain.AdminContact.Handle)
	}
	if result.Domain.AdminContact.Name != "Admin Person" {
		t.Errorf("AdminContact.Name = %q, want Admin Person", result.Domain.AdminContact.Name)
	}
}

func BenchmarkAUParser_Parse(b *testing.B) {
	p := NewAUParser()

	response := `Domain Name: example.com.au
Registry Domain ID: D12345678-AU
Registrar: Example Registrar
Status: ok
Registrant Contact ID: ABC123
Registrant Contact Name: Example Company
Name Server: ns1.example.com.au
Name Server: ns2.example.com.au
DNSSEC: unsigned
Last Modified: 2024-01-15T10:30:00Z
`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = p.Parse(response, "example.com.au")
	}
}
