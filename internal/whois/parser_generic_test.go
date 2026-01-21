package whois

import (
	"testing"
)

func TestGenericParser_Name(t *testing.T) {
	p := NewGenericParser()
	if p.Name() != "generic" {
		t.Errorf("Name() = %q, want generic", p.Name())
	}
}

func TestGenericParser_SupportsTLD(t *testing.T) {
	p := NewGenericParser()

	// Generic parser should support all TLDs
	tlds := []string{"com", "net", "org", "de", "cn", "xyz", "unknown"}
	for _, tld := range tlds {
		if !p.SupportsTLD(tld) {
			t.Errorf("SupportsTLD(%q) = false, want true", tld)
		}
	}
}

func TestGenericParser_Parse_BasicFields(t *testing.T) {
	p := NewGenericParser()

	response := `Domain Name: example.com
Registry Domain ID: 1234567890_DOMAIN_COM-VRSN
Registrar: Example Registrar, Inc.
Domain Status: clientTransferProhibited
Domain Status: clientDeleteProhibited
Name Server: ns1.example.com
Name Server: ns2.example.com
Creation Date: 2000-01-01T00:00:00Z
Updated Date: 2024-01-15T10:30:00Z
Registry Expiry Date: 2025-01-01T00:00:00Z
DNSSEC: unsigned
`
	result, err := p.Parse(response, "example.com")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	if result.Confidence != ConfidenceLow {
		t.Errorf("Confidence = %q, want low", result.Confidence)
	}

	pd := result.Domain

	if pd.DomainName != "example.com" {
		t.Errorf("DomainName = %q, want example.com", pd.DomainName)
	}

	if len(pd.Status) != 2 {
		t.Errorf("len(Status) = %d, want 2", len(pd.Status))
	}

	if len(pd.Nameservers) != 2 {
		t.Errorf("len(Nameservers) = %d, want 2", len(pd.Nameservers))
	} else if pd.Nameservers[0] != "ns1.example.com" {
		t.Errorf("Nameservers[0] = %q, want ns1.example.com", pd.Nameservers[0])
	}

	if pd.CreatedDate == nil {
		t.Error("CreatedDate should not be nil")
	} else if pd.CreatedDate.Year() != 2000 {
		t.Errorf("CreatedDate.Year() = %d, want 2000", pd.CreatedDate.Year())
	}

	if pd.UpdatedDate == nil {
		t.Error("UpdatedDate should not be nil")
	}

	if pd.ExpirationDate == nil {
		t.Error("ExpirationDate should not be nil")
	} else if pd.ExpirationDate.Year() != 2025 {
		t.Errorf("ExpirationDate.Year() = %d, want 2025", pd.ExpirationDate.Year())
	}

	if pd.Registrar == nil {
		t.Error("Registrar should not be nil")
	} else if pd.Registrar.Name != "Example Registrar, Inc." {
		t.Errorf("Registrar.Name = %q, want Example Registrar, Inc.", pd.Registrar.Name)
	}

	if pd.DNSSECSigned == nil {
		t.Error("DNSSECSigned should not be nil")
	} else if *pd.DNSSECSigned {
		t.Error("DNSSECSigned should be false for unsigned")
	}
}

func TestGenericParser_Parse_RegistrantInfo(t *testing.T) {
	p := NewGenericParser()

	response := `Domain Name: example.com
Registrant Name: John Doe
Registrant Organization: Example Corp
Registrant Email: john@example.com
`
	result, err := p.Parse(response, "example.com")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	pd := result.Domain

	if pd.Registrant == nil {
		t.Fatal("Registrant should not be nil")
	}

	if pd.Registrant.Name != "John Doe" {
		t.Errorf("Registrant.Name = %q, want John Doe", pd.Registrant.Name)
	}

	if pd.Registrant.Organization != "Example Corp" {
		t.Errorf("Registrant.Organization = %q, want Example Corp", pd.Registrant.Organization)
	}

	if pd.Registrant.Email != "john@example.com" {
		t.Errorf("Registrant.Email = %q, want john@example.com", pd.Registrant.Email)
	}
}

func TestGenericParser_Parse_DomainNameFallback(t *testing.T) {
	p := NewGenericParser()

	// Response without Domain Name field
	response := `Registrar: Example Registrar
Status: active
`
	result, err := p.Parse(response, "fallback.com")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	// Should use the provided domain as fallback
	if result.Domain.DomainName != "fallback.com" {
		t.Errorf("DomainName = %q, want fallback.com", result.Domain.DomainName)
	}
}

func TestGenericParser_Parse_RealCOMResponse(t *testing.T) {
	p := NewGenericParser()

	// Simulated real .com WHOIS response
	response := `   Domain Name: GOOGLE.COM
   Registry Domain ID: 2138514_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.markmonitor.com
   Registrar URL: http://www.markmonitor.com
   Updated Date: 2019-09-09T15:39:04Z
   Creation Date: 1997-09-15T04:00:00Z
   Registry Expiry Date: 2028-09-14T04:00:00Z
   Registrar: MarkMonitor Inc.
   Registrar IANA ID: 292
   Registrar Abuse Contact Email: abusecomplaints@markmonitor.com
   Registrar Abuse Contact Phone: +1.2086851750
   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
   Domain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited
   Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited
   Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited
   Name Server: NS1.GOOGLE.COM
   Name Server: NS2.GOOGLE.COM
   Name Server: NS3.GOOGLE.COM
   Name Server: NS4.GOOGLE.COM
   DNSSEC: unsigned
   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of whois database: 2024-01-15T12:00:00Z <<<
`
	result, err := p.Parse(response, "google.com")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	pd := result.Domain

	if pd.DomainName != "google.com" {
		t.Errorf("DomainName = %q, want google.com", pd.DomainName)
	}

	if len(pd.Status) != 6 {
		t.Errorf("len(Status) = %d, want 6", len(pd.Status))
	}

	if len(pd.Nameservers) != 4 {
		t.Errorf("len(Nameservers) = %d, want 4", len(pd.Nameservers))
	}

	if pd.Registrar == nil || pd.Registrar.Name != "MarkMonitor Inc." {
		t.Errorf("Registrar.Name = %v, want MarkMonitor Inc.", pd.Registrar)
	}

	if pd.CreatedDate == nil || pd.CreatedDate.Year() != 1997 {
		t.Errorf("CreatedDate = %v, want 1997", pd.CreatedDate)
	}

	if pd.ExpirationDate == nil || pd.ExpirationDate.Year() != 2028 {
		t.Errorf("ExpirationDate = %v, want 2028", pd.ExpirationDate)
	}
}

func TestParseDate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantYear int
		wantNil  bool
	}{
		{"RFC3339", "2024-01-15T10:30:00Z", 2024, false},
		{"ISO8601 with offset", "2024-01-15T10:30:00+01:00", 2024, false},
		{"Date only", "2024-01-15", 2024, false},
		{"Date with time", "2024-01-15 10:30:00", 2024, false},
		{"US format", "01/15/2024", 2024, false},
		{"European format", "15.01.2024", 2024, false},
		{"With timezone in parens", "2024-01-15T10:30:00+01:00 (CET)", 2024, false},
		{"Empty string", "", 0, true},
		{"Invalid", "not a date", 0, true},
		{"Partial date", "2024", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseDate(tt.input)
			if tt.wantNil {
				if result != nil {
					t.Errorf("parseDate(%q) = %v, want nil", tt.input, result)
				}
			} else {
				if result == nil {
					t.Errorf("parseDate(%q) = nil, want year %d", tt.input, tt.wantYear)
				} else if result.Year() != tt.wantYear {
					t.Errorf("parseDate(%q).Year() = %d, want %d", tt.input, result.Year(), tt.wantYear)
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
		{"ns1.example.com", "ns1.example.com"},
		{"NS1.EXAMPLE.COM", "ns1.example.com"},
		{"ns1.example.com.", "ns1.example.com"},
		{"  ns1.example.com  ", "ns1.example.com"},
		{"ns1.example.com 192.168.1.1", "ns1.example.com"},
		{"ns1.example.com 2001:db8::1", "ns1.example.com"},
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

func TestIsDNSSECSigned(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"signed", true},
		{"Signed", true},
		{"SIGNED", true},
		{"yes", true},
		{"signedDelegation", true},
		{"unsigned", false},
		{"Unsigned", false},
		{"no", false},
		{"inactive", false},
		{"", false},
		{"DS record present", true},
		{"dnskey available", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := isDNSSECSigned(tt.input)
			if result != tt.expected {
				t.Errorf("isDNSSECSigned(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestExtractCountry(t *testing.T) {
	tests := []struct {
		name     string
		response string
		expected string
	}{
		{
			name:     "Registrant Country field",
			response: "Registrant Country: US",
			expected: "US",
		},
		{
			name:     "Country field",
			response: "Country: DE",
			expected: "DE",
		},
		{
			name:     "No country field",
			response: "Domain Name: example.com",
			expected: "",
		},
		{
			name:     "Long country name",
			response: "Registrant Country: United States",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractCountry(tt.response)
			if result != tt.expected {
				t.Errorf("extractCountry() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestGenericParser_Parse_EmptyResponse(t *testing.T) {
	p := NewGenericParser()

	result, err := p.Parse("", "example.com")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	// Should still return a valid result with domain name from fallback
	if result.Domain.DomainName != "example.com" {
		t.Errorf("DomainName = %q, want example.com", result.Domain.DomainName)
	}
}

func TestGenericParser_Parse_MalformedResponse(t *testing.T) {
	p := NewGenericParser()

	// Malformed response with no valid fields
	response := `%%%%
This is not a WHOIS response
Random text
More garbage
`
	result, err := p.Parse(response, "example.com")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	// Should handle gracefully
	if result.Domain.DomainName != "example.com" {
		t.Errorf("DomainName = %q, want example.com", result.Domain.DomainName)
	}

	// No nameservers should be extracted
	if len(result.Domain.Nameservers) != 0 {
		t.Errorf("len(Nameservers) = %d, want 0", len(result.Domain.Nameservers))
	}
}

func TestGenericParser_Parse_DateFormats(t *testing.T) {
	p := NewGenericParser()

	tests := []struct {
		name     string
		response string
		wantYear int
	}{
		{
			name:     "ISO format",
			response: "Creation Date: 2020-05-15T10:30:00Z",
			wantYear: 2020,
		},
		{
			name:     "Simple date",
			response: "Creation Date: 2020-05-15",
			wantYear: 2020,
		},
		{
			name:     "With Registration Date",
			response: "Registration Date: 2019-03-20",
			wantYear: 2019,
		},
		{
			name:     "Registration Time format",
			response: "Registration Time: 2003-03-12 00:00:00",
			wantYear: 2003,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := p.Parse(tt.response, "test.com")
			if err != nil {
				t.Fatalf("Parse error = %v", err)
			}

			if result.Domain.CreatedDate == nil {
				t.Fatal("CreatedDate should not be nil")
			}

			if result.Domain.CreatedDate.Year() != tt.wantYear {
				t.Errorf("CreatedDate.Year() = %d, want %d", result.Domain.CreatedDate.Year(), tt.wantYear)
			}
		})
	}
}

func TestGenericParser_Parse_StoresRawResponse(t *testing.T) {
	p := NewGenericParser()

	response := "Domain Name: example.com\nStatus: active\n"
	result, err := p.Parse(response, "example.com")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	if result.Domain.RawResponse != response {
		t.Errorf("RawResponse not stored correctly")
	}
}

func BenchmarkGenericParser_Parse(b *testing.B) {
	p := NewGenericParser()

	response := `   Domain Name: GOOGLE.COM
   Registry Domain ID: 2138514_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.markmonitor.com
   Registrar URL: http://www.markmonitor.com
   Updated Date: 2019-09-09T15:39:04Z
   Creation Date: 1997-09-15T04:00:00Z
   Registry Expiry Date: 2028-09-14T04:00:00Z
   Registrar: MarkMonitor Inc.
   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Name Server: NS1.GOOGLE.COM
   Name Server: NS2.GOOGLE.COM
   Name Server: NS3.GOOGLE.COM
   Name Server: NS4.GOOGLE.COM
   DNSSEC: unsigned
`
	b.ResetTimer()
	for b.Loop() {
		_, _ = p.Parse(response, "google.com")
	}
}

func BenchmarkParseDate(b *testing.B) {
	dateStr := "2024-01-15T10:30:00Z"
	b.ResetTimer()
	for b.Loop() {
		_ = parseDate(dateStr)
	}
}
