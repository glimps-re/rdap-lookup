package parsers

import (
	"testing"
)

func TestCNParser_Name(t *testing.T) {
	p := NewCNParser()
	if p.Name() != "cn" {
		t.Errorf("Name() = %q, want cn", p.Name())
	}
}

func TestCNParser_SupportsTLD(t *testing.T) {
	p := NewCNParser()

	tests := []struct {
		tld      string
		expected bool
	}{
		{"cn", true},
		{"CN", true},
		{"com.cn", true},
		{"net.cn", true},
		{"org.cn", true},
		{"gov.cn", true},
		{"edu.cn", true},
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

func TestCNParser_Parse_BasicDomain(t *testing.T) {
	p := NewCNParser()

	response := `Domain Name: example.cn
ROID: 20030311s10001s00047706-cn
Domain Status: ok
Registrant ID: abc123def
Registrant: Example Company Ltd.
Registrant Contact Email: admin@example.cn
Sponsoring Registrar: Example Registrar
Name Server: ns1.example.cn
Name Server: ns2.example.cn
Registration Time: 2003-03-17 12:20:05
Expiration Time: 2025-03-17 12:48:36
DNSSEC: unsigned
`

	result, err := p.Parse(response, "example.cn")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	pd := result.Domain

	if pd.DomainName != "example.cn" {
		t.Errorf("DomainName = %q, want example.cn", pd.DomainName)
	}

	if pd.RegistryDomainID != "20030311s10001s00047706-cn" {
		t.Errorf("RegistryDomainID = %q, want 20030311s10001s00047706-cn", pd.RegistryDomainID)
	}

	if len(pd.Status) != 1 || pd.Status[0] != "ok" {
		t.Errorf("Status = %v, want [ok]", pd.Status)
	}

	if len(pd.Nameservers) != 2 {
		t.Errorf("len(Nameservers) = %d, want 2", len(pd.Nameservers))
	}

	if pd.CreatedDate == nil {
		t.Error("CreatedDate should not be nil")
	} else if pd.CreatedDate.Year() != 2003 {
		t.Errorf("CreatedDate.Year() = %d, want 2003", pd.CreatedDate.Year())
	}

	if pd.ExpirationDate == nil {
		t.Error("ExpirationDate should not be nil")
	} else if pd.ExpirationDate.Year() != 2025 {
		t.Errorf("ExpirationDate.Year() = %d, want 2025", pd.ExpirationDate.Year())
	}

	if pd.Registrar == nil {
		t.Error("Registrar should not be nil")
	} else if pd.Registrar.Name != "Example Registrar" {
		t.Errorf("Registrar.Name = %q, want Example Registrar", pd.Registrar.Name)
	}

	if pd.Registrant == nil {
		t.Fatal("Registrant should not be nil")
	}
	if pd.Registrant.Name != "Example Company Ltd." {
		t.Errorf("Registrant.Name = %q, want Example Company Ltd.", pd.Registrant.Name)
	}
	if pd.Registrant.Handle != "abc123def" {
		t.Errorf("Registrant.Handle = %q, want abc123def", pd.Registrant.Handle)
	}
	if pd.Registrant.Email != "admin@example.cn" {
		t.Errorf("Registrant.Email = %q, want admin@example.cn", pd.Registrant.Email)
	}

	if result.Confidence != "high" {
		t.Errorf("Confidence = %q, want high", result.Confidence)
	}

	if result.ParserName != "cn" {
		t.Errorf("ParserName = %q, want cn", result.ParserName)
	}
}

func TestCNParser_Parse_NotFound(t *testing.T) {
	p := NewCNParser()

	tests := []struct {
		name     string
		response string
	}{
		{"No matching record", "No matching record.\n"},
		{"Not found", "Domain not found\n"},
		{"No entries", "No entries found\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := p.Parse(tt.response, "notfound.cn")
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

func TestCNParser_Parse_DNSSEC(t *testing.T) {
	p := NewCNParser()

	tests := []struct {
		name     string
		response string
		expected bool
	}{
		{
			name:     "DNSSEC signed",
			response: "Domain Name: example.cn\nDNSSEC: signedDelegation\n",
			expected: true,
		},
		{
			name:     "DNSSEC unsigned",
			response: "Domain Name: example.cn\nDNSSEC: unsigned\n",
			expected: false,
		},
		{
			name:     "DNSSEC no",
			response: "Domain Name: example.cn\nDNSSEC: no\n",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := p.Parse(tt.response, "example.cn")
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

func TestCNParser_Parse_EmptyResponse(t *testing.T) {
	p := NewCNParser()

	result, err := p.Parse("", "example.cn")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	if result.Domain.DomainName != "example.cn" {
		t.Errorf("DomainName = %q, want example.cn", result.Domain.DomainName)
	}
}

func TestCNParser_Parse_CommentLines(t *testing.T) {
	p := NewCNParser()

	response := `% WHOIS data for .cn domains
% Rate limit exceeded
> More information at: https://whois.cnnic.cn
Domain Name: example.cn
Domain Status: ok
`

	result, err := p.Parse(response, "example.cn")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	if result.Domain.DomainName != "example.cn" {
		t.Errorf("DomainName = %q, want example.cn", result.Domain.DomainName)
	}
}

func TestParseCNDate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantYear int
		wantNil  bool
	}{
		{"CNNIC format", "2003-03-17 12:20:05", 2003, false},
		{"ISO format", "2024-01-15T10:30:00Z", 2024, false},
		{"Date only", "2024-01-15", 2024, false},
		{"Slash format", "2024/01/15", 2024, false},
		{"Empty string", "", 0, true},
		{"Invalid", "not a date", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseCNDate(tt.input)
			if tt.wantNil {
				if result != nil {
					t.Errorf("parseCNDate(%q) = %v, want nil", tt.input, result)
				}
			} else {
				if result == nil {
					t.Errorf("parseCNDate(%q) = nil, want year %d", tt.input, tt.wantYear)
				} else if result.Year() != tt.wantYear {
					t.Errorf("parseCNDate(%q).Year() = %d, want %d", tt.input, result.Year(), tt.wantYear)
				}
			}
		})
	}
}

func TestNormalizeCNNameserver(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ns1.example.cn", "ns1.example.cn"},
		{"NS1.EXAMPLE.CN", "ns1.example.cn"},
		{"ns1.example.cn.", "ns1.example.cn"},
		{"  ns1.example.cn  ", "ns1.example.cn"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeCNNameserver(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeCNNameserver(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestCNParser_Parse_RealWorldFormat(t *testing.T) {
	p := NewCNParser()

	// Simulated real-world CNNIC response format
	response := `Domain Name: baidu.cn
ROID: 20021209s10011s00047754-cn
Domain Status: serverDeleteProhibited
Domain Status: serverUpdateProhibited
Domain Status: serverTransferProhibited
Registrant ID: hc2092364843-cn
Registrant: Beijing Baidu Netcom Science Technology Co., Ltd.
Registrant Contact Email: domainname@baidu.com
Sponsoring Registrar: MarkMonitor, Inc.
Name Server: ns1.baidu.com
Name Server: ns2.baidu.com
Name Server: ns3.baidu.com
Name Server: ns4.baidu.com
Registration Time: 2002-12-09 12:00:00
Expiration Time: 2026-12-09 12:00:00
DNSSEC: unsigned
`

	result, err := p.Parse(response, "baidu.cn")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	pd := result.Domain

	if pd.DomainName != "baidu.cn" {
		t.Errorf("DomainName = %q, want baidu.cn", pd.DomainName)
	}

	if len(pd.Status) != 3 {
		t.Errorf("len(Status) = %d, want 3", len(pd.Status))
	}

	if len(pd.Nameservers) != 4 {
		t.Errorf("len(Nameservers) = %d, want 4", len(pd.Nameservers))
	}

	if pd.Registrant.Name != "Beijing Baidu Netcom Science Technology Co., Ltd." {
		t.Errorf("Registrant.Name = %q", pd.Registrant.Name)
	}

	if pd.CreatedDate == nil || pd.CreatedDate.Year() != 2002 {
		t.Errorf("CreatedDate = %v, want 2002", pd.CreatedDate)
	}
}

func BenchmarkCNParser_Parse(b *testing.B) {
	p := NewCNParser()

	response := `Domain Name: example.cn
ROID: 20030311s10001s00047706-cn
Domain Status: ok
Registrant ID: abc123def
Registrant: Example Company
Sponsoring Registrar: Example Registrar
Name Server: ns1.example.cn
Name Server: ns2.example.cn
Registration Time: 2003-03-17 12:20:05
Expiration Time: 2025-03-17 12:48:36
`

	b.ResetTimer()
	for b.Loop() {
		_, _ = p.Parse(response, "example.cn")
	}
}
