package parsers

import (
	"errors"
	"testing"

	"github.com/glimps-re/rdap-lookup/internal/whois"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestITParser_Name(t *testing.T) {
	p := NewITParser()
	if p.Name() != "it" {
		t.Errorf("Name() = %q, want it", p.Name())
	}
}

func TestITParser_SupportsTLD(t *testing.T) {
	p := NewITParser()

	tests := []struct {
		tld      string
		expected bool
	}{
		{"it", true},
		{"IT", true},
		{"It", true},
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

func TestITParser_Parse(t *testing.T) {
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
			response: `*********************************************************************
* Please note that the following result could be a subgroup of      *
* the data contained in the database.                               *
*********************************************************************

Domain:             example.it
Status:             ok

Created:            2000-01-15 00:00:00
Last Update:        2024-01-15 10:30:00
Expire Date:        2025-01-15

Registrant
  Organization:     Example S.r.l.

Admin Contact
  Name:             Admin Contact Name
  Organization:     Example S.r.l.

Technical Contacts
  Name:             Technical Contact Name
  Organization:     Example Hosting S.r.l.

Registrar
  Organization:     Example Registrar S.r.l.
  Name:             EXAMPLE-REG
  Web:              https://www.example-registrar.it

Nameservers
  ns1.example.it
  ns2.example.it
`,
			domain: "example.it",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName:     "example.it",
					Status:         []string{"ok"},
					Nameservers:    []string{"ns1.example.it", "ns2.example.it"},
					CreatedDate:    utc(2000, 1, 15, 0, 0, 0),
					UpdatedDate:    utc(2024, 1, 15, 10, 30, 0),
					ExpirationDate: utc(2025, 1, 15, 0, 0, 0),
					Registrar: &whois.ParsedEntity{
						Name:         "EXAMPLE-REG",
						Organization: "Example Registrar S.r.l.",
						Address:      "https://www.example-registrar.it",
					},
					Registrant: &whois.ParsedEntity{Organization: "Example S.r.l."},
					AdminContact: &whois.ParsedEntity{
						Name:         "Admin Contact Name",
						Organization: "Example S.r.l.",
					},
					TechContact: &whois.ParsedEntity{
						Name:         "Technical Contact Name",
						Organization: "Example Hosting S.r.l.",
					},
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "it",
			},
		},
		{
			name:     "not found: Status available",
			response: "Status:             AVAILABLE\n",
			domain:   "notfound.it",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName: "notfound.it",
					Status:     []string{"AVAILABLE"},
				},
				Confidence: whois.ConfidenceLow,
				ParserName: "it",
				Errors:     []string{"domain not found or available"},
				NotFound:   true,
			},
			wantErr: whois.ErrDomainNotFound,
		},
		{
			name:     "not found: Object not found",
			response: "Object not found\n",
			domain:   "notfound.it",
			want: &whois.ParseResult{
				Domain:     &whois.ParsedDomain{DomainName: "notfound.it"},
				Confidence: whois.ConfidenceLow,
				ParserName: "it",
				Errors:     []string{"domain not found or available"},
				NotFound:   true,
			},
			wantErr: whois.ErrDomainNotFound,
		},
		{
			name:     "not found: No entries",
			response: "No entries found\n",
			domain:   "notfound.it",
			want: &whois.ParseResult{
				Domain:     &whois.ParsedDomain{DomainName: "notfound.it"},
				Confidence: whois.ConfidenceLow,
				ParserName: "it",
				Errors:     []string{"domain not found or available"},
				NotFound:   true,
			},
			wantErr: whois.ErrDomainNotFound,
		},
		{
			name:   "empty response",
			domain: "example.it",
			want: &whois.ParseResult{
				Domain:     &whois.ParsedDomain{DomainName: "example.it"},
				Confidence: whois.ConfidenceHigh,
				ParserName: "it",
			},
			wantErr: whois.ErrNoRegistrationData,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := NewITParser()

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

func TestParseITDate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantYear int
		wantNil  bool
	}{
		{"NIC.it format", "2024-01-15 10:30:00", 2024, false},
		{"Date only", "2024-01-15", 2024, false},
		{"RFC3339", "2024-01-15T10:30:00Z", 2024, false},
		{"Empty string", "", 0, true},
		{"Invalid", "not a date", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseITDate(tt.input)
			if tt.wantNil {
				if result != nil {
					t.Errorf("parseITDate(%q) = %v, want nil", tt.input, result)
				}
			} else {
				if result == nil {
					t.Errorf("parseITDate(%q) = nil, want year %d", tt.input, tt.wantYear)
				} else if result.Year() != tt.wantYear {
					t.Errorf("parseITDate(%q).Year() = %d, want %d", tt.input, result.Year(), tt.wantYear)
				}
			}
		})
	}
}

func TestNormalizeITNameserver(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ns1.example.it", "ns1.example.it"},
		{"NS1.EXAMPLE.IT", "ns1.example.it"},
		{"ns1.example.it.", "ns1.example.it"},
		{"example", ""}, // No dot
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeITNameserver(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeITNameserver(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func BenchmarkITParser_Parse(b *testing.B) {
	p := NewITParser()

	response := `Domain:             example.it
Status:             ok
Created:            2000-01-15 00:00:00
Last Update:        2024-01-15 10:30:00
Expire Date:        2025-01-15
Registrant
  Organization:     Example S.r.l.
Registrar
  Organization:     Example Registrar S.r.l.
Nameservers
  ns1.example.it
  ns2.example.it
`

	b.ResetTimer()
	for b.Loop() {
		_, _ = p.Parse(response, "example.it")
	}
}
