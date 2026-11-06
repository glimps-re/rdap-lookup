package whois

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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

func TestGenericParser_Parse(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		response string
		domain   string
		want     *ParseResult
		wantErr  error
	}{
		{
			name: "basic fields",
			response: `Domain Name: example.com
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
`,
			domain: "example.com",
			want: &ParseResult{
				Domain: &ParsedDomain{
					DomainName:     "example.com",
					Status:         []string{"clientTransferProhibited", "clientDeleteProhibited"},
					Nameservers:    []string{"ns1.example.com", "ns2.example.com"},
					CreatedDate:    utc(2000, 1, 1, 0, 0, 0),
					UpdatedDate:    utc(2024, 1, 15, 10, 30, 0),
					ExpirationDate: utc(2025, 1, 1, 0, 0, 0),
					Registrar:      &ParsedEntity{Name: "Example Registrar, Inc."},
					DNSSECSigned:   ptr(false),
				},
				Confidence: ConfidenceLow,
				ParserName: "generic",
			},
		},
		{
			name: "registrant info",
			response: `Domain Name: example.com
Registrant Name: John Doe
Registrant Organization: Example Corp
Registrant Email: john@example.com
`,
			domain: "example.com",
			want: &ParseResult{
				Domain: &ParsedDomain{
					DomainName: "example.com",
					Registrant: &ParsedEntity{
						Name:         "John Doe",
						Organization: "Example Corp",
						Email:        "john@example.com",
					},
				},
				Confidence: ConfidenceLow,
				ParserName: "generic",
			},
		},
		{
			name:     "domain name falls back to the queried domain",
			response: "Registrar: Example Registrar\nStatus: active\n",
			domain:   "fallback.com",
			want: &ParseResult{
				Domain: &ParsedDomain{
					DomainName: "fallback.com",
					Status:     []string{"active"},
					Registrar:  &ParsedEntity{Name: "Example Registrar"},
				},
				Confidence: ConfidenceLow,
				ParserName: "generic",
			},
		},
		{
			name: "real .com response",
			response: `   Domain Name: GOOGLE.COM
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
`,
			domain: "google.com",
			want: &ParseResult{
				Domain: &ParsedDomain{
					DomainName:     "google.com",
					Status:         []string{"clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited", "clientTransferProhibited https://icann.org/epp#clientTransferProhibited", "clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited", "serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited", "serverTransferProhibited https://icann.org/epp#serverTransferProhibited", "serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited"},
					Nameservers:    []string{"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"},
					CreatedDate:    utc(1997, 9, 15, 4, 0, 0),
					UpdatedDate:    utc(2019, 9, 9, 15, 39, 4),
					ExpirationDate: utc(2028, 9, 14, 4, 0, 0),
					Registrar:      &ParsedEntity{Name: "MarkMonitor Inc."},
					DNSSECSigned:   ptr(false),
				},
				Confidence: ConfidenceLow,
				ParserName: "generic",
			},
		},
		{
			name:   "empty response",
			domain: "example.com",
			want: &ParseResult{
				Domain:     &ParsedDomain{DomainName: "example.com"},
				Confidence: ConfidenceLow,
				ParserName: "generic",
			},
			wantErr: ErrNoRegistrationData,
		},
		{
			name: "malformed response",
			response: `%%%%
This is not a WHOIS response
Random text
More garbage
`,
			domain: "example.com",
			want: &ParseResult{
				Domain:     &ParsedDomain{DomainName: "example.com"},
				Confidence: ConfidenceLow,
				ParserName: "generic",
			},
			wantErr: ErrNoRegistrationData,
		},
		{
			name:     "date format: ISO",
			response: "Creation Date: 2020-05-15T10:30:00Z",
			domain:   "test.com",
			want: &ParseResult{
				Domain: &ParsedDomain{
					DomainName:  "test.com",
					CreatedDate: utc(2020, 5, 15, 10, 30, 0),
				},
				Confidence: ConfidenceLow,
				ParserName: "generic",
			},
		},
		{
			name:     "date format: simple date",
			response: "Creation Date: 2020-05-15",
			domain:   "test.com",
			want: &ParseResult{
				Domain: &ParsedDomain{
					DomainName:  "test.com",
					CreatedDate: utc(2020, 5, 15, 0, 0, 0),
				},
				Confidence: ConfidenceLow,
				ParserName: "generic",
			},
		},
		{
			name:     "date format: Registration Date",
			response: "Registration Date: 2019-03-20",
			domain:   "test.com",
			want: &ParseResult{
				Domain: &ParsedDomain{
					DomainName:  "test.com",
					CreatedDate: utc(2019, 3, 20, 0, 0, 0),
				},
				Confidence: ConfidenceLow,
				ParserName: "generic",
			},
		},
		{
			name:     "date format: Registration Time",
			response: "Registration Time: 2003-03-12 00:00:00",
			domain:   "test.com",
			want: &ParseResult{
				Domain: &ParsedDomain{
					DomainName:  "test.com",
					CreatedDate: utc(2003, 3, 12, 0, 0, 0),
				},
				Confidence: ConfidenceLow,
				ParserName: "generic",
			},
		},
		{
			name:     "raw response is stored",
			response: "Domain Name: example.com\nStatus: active\n",
			domain:   "example.com",
			want: &ParseResult{
				Domain: &ParsedDomain{
					DomainName: "example.com",
					Status:     []string{"active"},
				},
				Confidence: ConfidenceLow,
				ParserName: "generic",
			},
			wantErr: ErrNoRegistrationData,
		},
		{
			name:     "not found: no match line",
			response: "No match for \"FREE.XX\".\n",
			domain:   "free.xx",
			want: &ParseResult{
				Domain:     &ParsedDomain{DomainName: "free.xx"},
				Confidence: ConfidenceLow,
				ParserName: "generic",
				Errors:     []string{"domain not found"},
				NotFound:   true,
			},
			wantErr: ErrDomainNotFound,
		},
		{
			name:     "not found: comment-marked not-found line",
			response: "% No entries found for the selected source(s).\n",
			domain:   "free.xx",
			want: &ParseResult{
				Domain:     &ParsedDomain{DomainName: "free.xx"},
				Confidence: ConfidenceLow,
				ParserName: "generic",
				Errors:     []string{"domain not found"},
				NotFound:   true,
			},
			wantErr: ErrDomainNotFound,
		},
		{
			name:     "not found: status free",
			response: "Domain: free.xx\nStatus: free\n",
			domain:   "free.xx",
			want: &ParseResult{
				Domain: &ParsedDomain{
					DomainName: "free.xx",
					Status:     []string{"free"},
				},
				Confidence: ConfidenceLow,
				ParserName: "generic",
				Errors:     []string{"domain not found"},
				NotFound:   true,
			},
			wantErr: ErrDomainNotFound,
		},
		{
			name:     "not found: phrase inside a sentence is not trusted",
			response: "The requested domain free.xx was not found in the database.\n",
			domain:   "free.xx",
			want: &ParseResult{
				Domain:     &ParsedDomain{DomainName: "free.xx"},
				Confidence: ConfidenceLow,
				ParserName: "generic",
			},
			wantErr: ErrNoRegistrationData,
		},
		{
			name: "not found: registered domain mentioning not found",
			response: `Domain Name: taken.xx
Name Server: ns1.taken.xx
Creation Date: 2020-01-01
Remarks: report abuse, page not found errors to abuse@registry.xx
`,
			domain: "free.xx",
			want: &ParseResult{
				Domain: &ParsedDomain{
					DomainName:  "taken.xx",
					Nameservers: []string{"ns1.taken.xx"},
					CreatedDate: utc(2020, 1, 1, 0, 0, 0),
				},
				Confidence: ConfidenceLow,
				ParserName: "generic",
			},
		},
		{
			name:     "not found: unrecognized empty answer",
			response: "Query rate exceeded\n",
			domain:   "free.xx",
			want: &ParseResult{
				Domain:     &ParsedDomain{DomainName: "free.xx"},
				Confidence: ConfidenceLow,
				ParserName: "generic",
			},
			wantErr: ErrNoRegistrationData,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := NewGenericParser()

			got, err := p.Parse(tc.response, tc.domain)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.IgnoreFields(ParsedDomain{}, "RawResponse")); diff != "" {
				t.Errorf("Parse() mismatch (-want +got):\n%s", diff)
			}
			if got.Domain.RawResponse != tc.response {
				t.Errorf("RawResponse = %q, want %q", got.Domain.RawResponse, tc.response)
			}
			if err := got.Err(); !errors.Is(err, tc.wantErr) {
				t.Errorf("Err() = %v, want %v", err, tc.wantErr)
			}
		})
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
