package parsers

import (
	"errors"
	"testing"

	"github.com/glimps-re/rdap-lookup/internal/whois"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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

func TestAUParser_Parse(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		response string
		domain   string
		want     *whois.ParseResult
		wantErr  error
	}{
		{
			name: "basic domain",
			response: `Domain Name: example.com.au
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
`,
			domain: "example.com.au",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName:       "example.com.au",
					RegistryDomainID: "D12345678-AU",
					Status:           []string{"ok"},
					Nameservers:      []string{"ns1.example.com.au", "ns2.example.com.au"},
					UpdatedDate:      utc(2024, 1, 15, 10, 30, 0),
					Registrar:        &whois.ParsedEntity{Name: "Example Registrar Pty Ltd"},
					Registrant: &whois.ParsedEntity{
						Handle: "ABC123",
						Name:   "Example Company Pty Ltd",
					},
					TechContact: &whois.ParsedEntity{
						Handle: "XYZ789",
						Name:   "Technical Support",
					},
					DNSSECSigned: new(false),
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "au",
			},
		},
		{
			name: "with dates",
			response: `Domain Name: example.com.au
Status: ok
Creation Date: 2000-05-20T00:00:00Z
Last Modified: 2024-01-15T10:30:00Z
Registry Expiry Date: 2025-05-20T00:00:00Z
`,
			domain: "example.com.au",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName:     "example.com.au",
					Status:         []string{"ok"},
					CreatedDate:    utc(2000, 5, 20, 0, 0, 0),
					UpdatedDate:    utc(2024, 1, 15, 10, 30, 0),
					ExpirationDate: utc(2025, 5, 20, 0, 0, 0),
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "au",
			},
		},
		{
			name:     "not found: No Data Found",
			response: "No Data Found\n",
			domain:   "notfound.com.au",
			want: &whois.ParseResult{
				Domain:     &whois.ParsedDomain{DomainName: "notfound.com.au"},
				Confidence: whois.ConfidenceLow,
				ParserName: "au",
				Errors:     []string{"domain not found"},
				NotFound:   true,
			},
			wantErr: whois.ErrDomainNotFound,
		},
		{
			name:     "not found: Not found",
			response: "Domain not found\n",
			domain:   "notfound.com.au",
			want: &whois.ParseResult{
				Domain:     &whois.ParsedDomain{DomainName: "notfound.com.au"},
				Confidence: whois.ConfidenceLow,
				ParserName: "au",
				Errors:     []string{"domain not found"},
				NotFound:   true,
			},
			wantErr: whois.ErrDomainNotFound,
		},
		{
			name:     "not found: No entries",
			response: "No entries found\n",
			domain:   "notfound.com.au",
			want: &whois.ParseResult{
				Domain:     &whois.ParsedDomain{DomainName: "notfound.com.au"},
				Confidence: whois.ConfidenceLow,
				ParserName: "au",
				Errors:     []string{"domain not found"},
				NotFound:   true,
			},
			wantErr: whois.ErrDomainNotFound,
		},
		{
			name:     "not found: No match",
			response: "No match for domain\n",
			domain:   "notfound.com.au",
			want: &whois.ParseResult{
				Domain:     &whois.ParsedDomain{DomainName: "notfound.com.au"},
				Confidence: whois.ConfidenceLow,
				ParserName: "au",
				Errors:     []string{"domain not found"},
				NotFound:   true,
			},
			wantErr: whois.ErrDomainNotFound,
		},
		{
			name:     "DNSSEC: DNSSEC signed",
			response: "Domain Name: example.com.au\nDNSSEC: signedDelegation\n",
			domain:   "example.com.au",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName:   "example.com.au",
					DNSSECSigned: new(true),
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "au",
			},
			wantErr: whois.ErrNoRegistrationData,
		},
		{
			name:     "DNSSEC: DNSSEC unsigned",
			response: "Domain Name: example.com.au\nDNSSEC: unsigned\n",
			domain:   "example.com.au",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName:   "example.com.au",
					DNSSECSigned: new(false),
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "au",
			},
			wantErr: whois.ErrNoRegistrationData,
		},
		{
			name:     "DNSSEC: DNSSEC no",
			response: "Domain Name: example.com.au\nDNSSEC: no\n",
			domain:   "example.com.au",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName:   "example.com.au",
					DNSSECSigned: new(false),
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "au",
			},
			wantErr: whois.ErrNoRegistrationData,
		},
		{
			name:     "DNSSEC: DNSSEC N",
			response: "Domain Name: example.com.au\nDNSSEC: N\n",
			domain:   "example.com.au",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName:   "example.com.au",
					DNSSECSigned: new(false),
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "au",
			},
			wantErr: whois.ErrNoRegistrationData,
		},
		{
			name:     "status with URLs stripped",
			response: "Domain Name: example.com.au\nDomain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\nDomain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\n",
			domain:   "example.com.au",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName: "example.com.au",
					Status:     []string{"clientTransferProhibited", "clientDeleteProhibited"},
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "au",
			},
			wantErr: whois.ErrNoRegistrationData,
		},
		{
			name:   "empty response",
			domain: "example.com.au",
			want: &whois.ParseResult{
				Domain:     &whois.ParsedDomain{DomainName: "example.com.au"},
				Confidence: whois.ConfidenceHigh,
				ParserName: "au",
			},
			wantErr: whois.ErrNoRegistrationData,
		},
		{
			name: "comment lines",
			response: `% WHOIS data for .au domains
% Rate limit exceeded
# Comment line
Domain Name: example.com.au
Status: ok
`,
			domain: "example.com.au",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName: "example.com.au",
					Status:     []string{"ok"},
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "au",
			},
			wantErr: whois.ErrNoRegistrationData,
		},
		{
			name: "real-world auDA format",
			response: `Domain Name: google.com.au
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
`,
			domain: "google.com.au",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName:       "google.com.au",
					RegistryDomainID: "D12345678-AU",
					Status:           []string{"clientDeleteProhibited", "clientTransferProhibited", "clientUpdateProhibited"},
					Nameservers:      []string{"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"},
					UpdatedDate:      utc(2023, 12, 15, 10, 30, 0),
					Registrar: &whois.ParsedEntity{
						Name:  "MarkMonitor Inc.",
						Email: "abusecomplaints@markmonitor.com",
						Phone: "+1.2083895740",
					},
					Registrant: &whois.ParsedEntity{
						Handle: "GOOG123",
						Name:   "Domain Administrator",
					},
					TechContact: &whois.ParsedEntity{
						Handle: "TECH456",
						Name:   "Technical Support",
					},
					DNSSECSigned: new(false),
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "au",
			},
		},
		{
			name:     "admin contact",
			response: "Domain Name: example.com.au\nAdmin Contact ID: ADM001\nAdmin Contact Name: Admin Person\n",
			domain:   "example.com.au",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName: "example.com.au",
					AdminContact: &whois.ParsedEntity{
						Handle: "ADM001",
						Name:   "Admin Person",
					},
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "au",
			},
		},
		{
			name: "registered domain mentioning not found",
			response: `Domain Name: example.com.au
Registrar: Example Registrar Pty Ltd
Name Server: ns1.example.com.au
Last Modified: 2024-01-15T10:30:00Z
Remarks: page not found errors can be reported to the registrar
`,
			domain: "example.com.au",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName:  "example.com.au",
					Nameservers: []string{"ns1.example.com.au"},
					UpdatedDate: utc(2024, 1, 15, 10, 30, 0),
					Registrar:   &whois.ParsedEntity{Name: "Example Registrar Pty Ltd"},
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "au",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := NewAUParser()

			got, err := p.Parse(tc.response, tc.domain)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.IgnoreFields(whois.ParsedDomain{}, "RawResponse")); diff != "" {
				t.Errorf("Parse() mismatch (-want +got):\n%s", diff)
			}
			if err := got.Err(); !errors.Is(err, tc.wantErr) {
				t.Errorf("Err() = %v, want %v", err, tc.wantErr)
			}
		})
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
	for b.Loop() {
		_, _ = p.Parse(response, "example.com.au")
	}
}
