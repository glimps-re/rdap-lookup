package parsers

import (
	"errors"
	"testing"

	"github.com/glimps-re/rdap-lookup/internal/whois"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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

func TestCNParser_Parse(t *testing.T) {
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
			response: `Domain Name: example.cn
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
`,
			domain: "example.cn",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName:       "example.cn",
					RegistryDomainID: "20030311s10001s00047706-cn",
					Status:           []string{"ok"},
					Nameservers:      []string{"ns1.example.cn", "ns2.example.cn"},
					CreatedDate:      utc(2003, 3, 17, 12, 20, 5),
					ExpirationDate:   utc(2025, 3, 17, 12, 48, 36),
					Registrar:        &whois.ParsedEntity{Name: "Example Registrar"},
					Registrant: &whois.ParsedEntity{
						Handle: "abc123def",
						Name:   "Example Company Ltd.",
						Email:  "admin@example.cn",
					},
					DNSSECSigned: new(false),
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "cn",
			},
		},
		{
			name:     "not found: No matching record",
			response: "No matching record.\n",
			domain:   "notfound.cn",
			want: &whois.ParseResult{
				Domain:     &whois.ParsedDomain{DomainName: "notfound.cn"},
				Confidence: whois.ConfidenceLow,
				ParserName: "cn",
				Errors:     []string{"domain not found"},
				NotFound:   true,
			},
			wantErr: whois.ErrDomainNotFound,
		},
		{
			name:     "not found: Not found",
			response: "Domain not found\n",
			domain:   "notfound.cn",
			want: &whois.ParseResult{
				Domain:     &whois.ParsedDomain{DomainName: "notfound.cn"},
				Confidence: whois.ConfidenceLow,
				ParserName: "cn",
				Errors:     []string{"domain not found"},
				NotFound:   true,
			},
			wantErr: whois.ErrDomainNotFound,
		},
		{
			name:     "not found: No entries",
			response: "No entries found\n",
			domain:   "notfound.cn",
			want: &whois.ParseResult{
				Domain:     &whois.ParsedDomain{DomainName: "notfound.cn"},
				Confidence: whois.ConfidenceLow,
				ParserName: "cn",
				Errors:     []string{"domain not found"},
				NotFound:   true,
			},
			wantErr: whois.ErrDomainNotFound,
		},
		{
			name:     "DNSSEC: DNSSEC signed",
			response: "Domain Name: example.cn\nDNSSEC: signedDelegation\n",
			domain:   "example.cn",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName:   "example.cn",
					DNSSECSigned: new(true),
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "cn",
			},
			wantErr: whois.ErrNoRegistrationData,
		},
		{
			name:     "DNSSEC: DNSSEC unsigned",
			response: "Domain Name: example.cn\nDNSSEC: unsigned\n",
			domain:   "example.cn",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName:   "example.cn",
					DNSSECSigned: new(false),
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "cn",
			},
			wantErr: whois.ErrNoRegistrationData,
		},
		{
			name:     "DNSSEC: DNSSEC no",
			response: "Domain Name: example.cn\nDNSSEC: no\n",
			domain:   "example.cn",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName:   "example.cn",
					DNSSECSigned: new(false),
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "cn",
			},
			wantErr: whois.ErrNoRegistrationData,
		},
		{
			name:   "empty response",
			domain: "example.cn",
			want: &whois.ParseResult{
				Domain:     &whois.ParsedDomain{DomainName: "example.cn"},
				Confidence: whois.ConfidenceHigh,
				ParserName: "cn",
			},
			wantErr: whois.ErrNoRegistrationData,
		},
		{
			name: "comment lines",
			response: `% WHOIS data for .cn domains
% Rate limit exceeded
> More information at: https://whois.cnnic.cn
Domain Name: example.cn
Domain Status: ok
`,
			domain: "example.cn",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName: "example.cn",
					Status:     []string{"ok"},
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "cn",
			},
			wantErr: whois.ErrNoRegistrationData,
		},
		{
			name: "real-world CNNIC format",
			response: `Domain Name: baidu.cn
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
`,
			domain: "baidu.cn",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName:       "baidu.cn",
					RegistryDomainID: "20021209s10011s00047754-cn",
					Status:           []string{"serverDeleteProhibited", "serverUpdateProhibited", "serverTransferProhibited"},
					Nameservers:      []string{"ns1.baidu.com", "ns2.baidu.com", "ns3.baidu.com", "ns4.baidu.com"},
					CreatedDate:      utc(2002, 12, 9, 12, 0, 0),
					ExpirationDate:   utc(2026, 12, 9, 12, 0, 0),
					Registrar:        &whois.ParsedEntity{Name: "MarkMonitor, Inc."},
					Registrant: &whois.ParsedEntity{
						Handle: "hc2092364843-cn",
						Name:   "Beijing Baidu Netcom Science Technology Co., Ltd.",
						Email:  "domainname@baidu.com",
					},
					DNSSECSigned: new(false),
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "cn",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := NewCNParser()

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
