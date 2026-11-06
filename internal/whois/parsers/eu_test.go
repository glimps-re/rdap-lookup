package parsers

import (
	"errors"
	"testing"

	"github.com/glimps-re/rdap-lookup/internal/whois"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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

func TestEUParser_Parse(t *testing.T) {
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
			response: `Domain: example.eu
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
`,
			domain: "example.eu",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName:  "example.eu",
					Nameservers: []string{"ns1.example.eu", "ns2.example.eu"},
					Registrar: &whois.ParsedEntity{
						Name:    "Example Registrar",
						Address: "https://www.example-registrar.eu",
					},
					TechContact: &whois.ParsedEntity{
						Name:         "Technical Contact",
						Organization: "Example Tech Ltd",
						Email:        "tech@example.eu",
						Phone:        "+32.123456789",
					},
					DNSSECSigned: new(true),
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "eu",
			},
		},
		{
			name:     "not found: Status available",
			response: "Status: AVAILABLE\n",
			domain:   "notfound.eu",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName: "notfound.eu",
					Status:     []string{"AVAILABLE"},
				},
				Confidence: whois.ConfidenceLow,
				ParserName: "eu",
				Errors:     []string{"domain not found or available"},
				NotFound:   true,
			},
			wantErr: whois.ErrDomainNotFound,
		},
		{
			name:     "not found: Not found",
			response: "Domain not found\n",
			domain:   "notfound.eu",
			want: &whois.ParseResult{
				Domain:     &whois.ParsedDomain{DomainName: "notfound.eu"},
				Confidence: whois.ConfidenceLow,
				ParserName: "eu",
				Errors:     []string{"domain not found or available"},
				NotFound:   true,
			},
			wantErr: whois.ErrDomainNotFound,
		},
		{
			name:     "not found: No entries",
			response: "No entries found\n",
			domain:   "notfound.eu",
			want: &whois.ParseResult{
				Domain:     &whois.ParsedDomain{DomainName: "notfound.eu"},
				Confidence: whois.ConfidenceLow,
				ParserName: "eu",
				Errors:     []string{"domain not found or available"},
				NotFound:   true,
			},
			wantErr: whois.ErrDomainNotFound,
		},
		{
			name:   "empty response",
			domain: "example.eu",
			want: &whois.ParseResult{
				Domain:     &whois.ParsedDomain{DomainName: "example.eu"},
				Confidence: whois.ConfidenceHigh,
				ParserName: "eu",
			},
			wantErr: whois.ErrNoRegistrationData,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := NewEUParser()

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
