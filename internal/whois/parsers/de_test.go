package parsers

import (
	"errors"
	"testing"

	"github.com/glimps-re/rdap-lookup/internal/whois"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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

func TestDEParser_Parse(t *testing.T) {
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
			response: `Domain: example.de
Nserver: ns1.example.de
Nserver: ns2.example.de
Status: connect
Changed: 2024-01-15T10:30:00+01:00
RegCreatedDate: 2000-05-20T00:00:00+02:00
`,
			domain: "example.de",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName:  "example.de",
					Status:      []string{"connect"},
					Nameservers: []string{"ns1.example.de", "ns2.example.de"},
					CreatedDate: utc(2000, 5, 19, 22, 0, 0),
					UpdatedDate: utc(2024, 1, 15, 9, 30, 0),
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "de",
			},
		},
		{
			name: "with contacts",
			response: `Domain: example.de
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
`,
			domain: "example.de",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName:  "example.de",
					Status:      []string{"connect"},
					Nameservers: []string{"ns1.example.de"},
					Registrant: &whois.ParsedEntity{
						Name:         "John Doe",
						Organization: "Example GmbH",
						Email:        "holder@example.de",
						Phone:        "+49.301234567",
						Address:      "Example Street 123",
						Country:      "DE",
						City:         "Berlin",
						PostalCode:   "10115",
					},
					TechContact: &whois.ParsedEntity{
						Name:         "Technical Support",
						Organization: "Hosting Provider",
						Email:        "tech@provider.de",
					},
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "de",
			},
		},
		{
			name:     "not found: Status free",
			response: "Status: free\n",
			domain:   "notfound.de",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName: "notfound.de",
					Status:     []string{"free"},
				},
				Confidence: whois.ConfidenceLow,
				ParserName: "de",
				Errors:     []string{"domain not found or free"},
				NotFound:   true,
			},
			wantErr: whois.ErrDomainNotFound,
		},
		{
			name:     "not found: Object not found",
			response: "% Object not found\n",
			domain:   "notfound.de",
			want: &whois.ParseResult{
				Domain:     &whois.ParsedDomain{DomainName: "notfound.de"},
				Confidence: whois.ConfidenceLow,
				ParserName: "de",
				Errors:     []string{"domain not found or free"},
				NotFound:   true,
			},
			wantErr: whois.ErrDomainNotFound,
		},
		{
			name:     "not found: No entries found",
			response: "No entries found for the selected source(s).\n",
			domain:   "notfound.de",
			want: &whois.ParseResult{
				Domain:     &whois.ParsedDomain{DomainName: "notfound.de"},
				Confidence: whois.ConfidenceLow,
				ParserName: "de",
				Errors:     []string{"domain not found or free"},
				NotFound:   true,
			},
			wantErr: whois.ErrDomainNotFound,
		},
		{
			name:     "DNSSEC: DNSKEY present",
			response: "Domain: example.de\nDnskey: 257 3 8 AwEAAb...\n",
			domain:   "example.de",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName:   "example.de",
					DNSSECSigned: new(true),
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "de",
			},
			wantErr: whois.ErrNoRegistrationData,
		},
		{
			name:     "DNSSEC: DNSSEC signed",
			response: "Domain: example.de\nDnssec: Y\n",
			domain:   "example.de",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName:   "example.de",
					DNSSECSigned: new(true),
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "de",
			},
			wantErr: whois.ErrNoRegistrationData,
		},
		{
			name:     "DNSSEC: DNSSEC unsigned",
			response: "Domain: example.de\nDnssec: N\n",
			domain:   "example.de",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName:   "example.de",
					DNSSECSigned: new(false),
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "de",
			},
			wantErr: whois.ErrNoRegistrationData,
		},
		{
			name:     "DNSSEC: DNSSEC unsigned explicit",
			response: "Domain: example.de\nDnssec: unsigned\n",
			domain:   "example.de",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName:   "example.de",
					DNSSECSigned: new(false),
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "de",
			},
			wantErr: whois.ErrNoRegistrationData,
		},
		{
			name:     "nameserver with IP stripped",
			response: "Domain: example.de\nNserver: ns1.example.de 192.168.1.1\nNserver: ns2.example.de 192.168.1.2\n",
			domain:   "example.de",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName:  "example.de",
					Nameservers: []string{"ns1.example.de", "ns2.example.de"},
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "de",
			},
		},
		{
			name:   "empty response falls back to domain",
			domain: "example.de",
			want: &whois.ParseResult{
				Domain:     &whois.ParsedDomain{DomainName: "example.de"},
				Confidence: whois.ConfidenceHigh,
				ParserName: "de",
			},
			wantErr: whois.ErrNoRegistrationData,
		},
		{
			name: "real-world DENIC format",
			response: `% Restricted rights.
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
`,
			domain: "google.de",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName:  "google.de",
					Status:      []string{"connect"},
					Nameservers: []string{"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"},
					UpdatedDate: utc(2023, 9, 15, 6, 25, 21),
					TechContact: &whois.ParsedEntity{
						Name:         "DNS Admin",
						Organization: "Google Germany GmbH",
						Email:        "dns-admin@google.com",
						Phone:        "+49.40808179000",
						Fax:          "+49.40808179001",
						Address:      "ABC-Strasse 19",
						Country:      "DE",
						City:         "Hamburg",
						PostalCode:   "20354",
					},
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "de",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := NewDEParser()

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
	for b.Loop() {
		_, _ = p.Parse(response, "example.de")
	}
}
