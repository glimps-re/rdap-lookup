package parsers

import (
	"errors"
	"testing"

	"github.com/glimps-re/rdap-lookup/internal/whois"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestRUParser_Name(t *testing.T) {
	p := NewRUParser()
	if p.Name() != "ru" {
		t.Errorf("Name() = %q, want ru", p.Name())
	}
}

func TestRUParser_SupportsTLD(t *testing.T) {
	p := NewRUParser()

	tests := []struct {
		tld      string
		expected bool
	}{
		{"ru", true},
		{"RU", true},
		{"su", true},
		{"SU", true},
		{"rf", true},
		{"xn--p1ai", true}, // .рф in punycode
		{"com", false},
		{"de", false},
		{"russia", false},
	}

	for _, tt := range tests {
		t.Run(tt.tld, func(t *testing.T) {
			if got := p.SupportsTLD(tt.tld); got != tt.expected {
				t.Errorf("SupportsTLD(%q) = %v, want %v", tt.tld, got, tt.expected)
			}
		})
	}
}

func TestRUParser_Parse(t *testing.T) {
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
			response: `domain:        EXAMPLE.RU
nserver:       ns1.example.ru.
nserver:       ns2.example.ru.
state:         REGISTERED, DELEGATED, VERIFIED
org:           Example Organization LLC
registrar:     REGISTRAR-RU
created:       2000-01-15T00:00:00Z
paid-till:     2025-01-15T00:00:00Z
source:        TCI
`,
			domain: "example.ru",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName:     "example.ru",
					Status:         []string{"REGISTERED", "DELEGATED", "VERIFIED"},
					Nameservers:    []string{"ns1.example.ru", "ns2.example.ru"},
					CreatedDate:    utc(2000, 1, 15, 0, 0, 0),
					ExpirationDate: utc(2025, 1, 15, 0, 0, 0),
					Registrar:      &whois.ParsedEntity{Name: "REGISTRAR-RU"},
					Registrant:     &whois.ParsedEntity{Organization: "Example Organization LLC"},
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "ru",
			},
		},
		{
			name: "with person",
			response: `domain:        EXAMPLE.RU
nserver:       ns1.example.ru.
state:         REGISTERED, DELEGATED
person:        Private Person
e-mail:        person@example.ru
phone:         +7.4951234567
registrar:     REGISTRAR-RU
created:       2010-05-20T00:00:00Z
paid-till:     2025-05-20T00:00:00Z
source:        TCI
`,
			domain: "example.ru",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName:     "example.ru",
					Status:         []string{"REGISTERED", "DELEGATED"},
					Nameservers:    []string{"ns1.example.ru"},
					CreatedDate:    utc(2010, 5, 20, 0, 0, 0),
					ExpirationDate: utc(2025, 5, 20, 0, 0, 0),
					Registrar:      &whois.ParsedEntity{Name: "REGISTRAR-RU"},
					Registrant: &whois.ParsedEntity{
						Name:  "Private Person",
						Email: "person@example.ru",
						Phone: "+7.4951234567",
					},
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "ru",
			},
		},
		{
			name:     "not found: No entries found",
			response: "No entries found for the selected source(s).\n",
			domain:   "notfound.ru",
			want: &whois.ParseResult{
				Domain:     &whois.ParsedDomain{DomainName: "notfound.ru"},
				Confidence: whois.ConfidenceLow,
				ParserName: "ru",
				Errors:     []string{"domain not found"},
				NotFound:   true,
			},
			wantErr: whois.ErrDomainNotFound,
		},
		{
			name:     "not found: No object found",
			response: "% No object found\n",
			domain:   "notfound.ru",
			want: &whois.ParseResult{
				Domain:     &whois.ParsedDomain{DomainName: "notfound.ru"},
				Confidence: whois.ConfidenceLow,
				ParserName: "ru",
				Errors:     []string{"domain not found"},
				NotFound:   true,
			},
			wantErr: whois.ErrDomainNotFound,
		},
		{
			name:     "not found: Object not found",
			response: "Object not found\n",
			domain:   "notfound.ru",
			want: &whois.ParseResult{
				Domain:     &whois.ParsedDomain{DomainName: "notfound.ru"},
				Confidence: whois.ConfidenceLow,
				ParserName: "ru",
				Errors:     []string{"domain not found"},
				NotFound:   true,
			},
			wantErr: whois.ErrDomainNotFound,
		},
		{
			name:   "empty response",
			domain: "example.ru",
			want: &whois.ParseResult{
				Domain:     &whois.ParsedDomain{DomainName: "example.ru"},
				Confidence: whois.ConfidenceHigh,
				ParserName: "ru",
			},
			wantErr: whois.ErrNoRegistrationData,
		},
		{
			name: "comment lines",
			response: `% By querying this database, you agree to abide by
% the following policy
% https://www.tcinet.ru/whois-terms

domain:        EXAMPLE.RU
state:         REGISTERED, DELEGATED
registrar:     REGISTRAR-RU
`,
			domain: "example.ru",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName: "example.ru",
					Status:     []string{"REGISTERED", "DELEGATED"},
					Registrar:  &whois.ParsedEntity{Name: "REGISTRAR-RU"},
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "ru",
			},
		},
		{
			name: "real-world TCINET format",
			response: `% By querying this database, you agree to abide by
% the following policy
% https://www.tcinet.ru/content/document/42

domain:        YANDEX.RU
nserver:       ns1.yandex.ru.
nserver:       ns2.yandex.ru.
nserver:       ns9.z5h64q92x9.net.
state:         REGISTERED, DELEGATED, VERIFIED
org:           YANDEX LLC
registrar:     RU-CENTER-RU
admin-contact: https://www.nic.ru/whois
created:       1997-09-23T09:45:07Z
paid-till:     2025-09-30T21:00:00Z
free-date:     2025-11-01
source:        TCI

Last updated on 2024-01-15T10:30:00Z
`,
			domain: "yandex.ru",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName:     "yandex.ru",
					Status:         []string{"REGISTERED", "DELEGATED", "VERIFIED"},
					Nameservers:    []string{"ns1.yandex.ru", "ns2.yandex.ru", "ns9.z5h64q92x9.net"},
					CreatedDate:    utc(1997, 9, 23, 9, 45, 7),
					ExpirationDate: utc(2025, 9, 30, 21, 0, 0),
					Registrar:      &whois.ParsedEntity{Name: "RU-CENTER-RU"},
					Registrant:     &whois.ParsedEntity{Organization: "YANDEX LLC"},
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "ru",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := NewRUParser()

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

func TestParseRUDate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantYear int
		wantNil  bool
	}{
		{"RFC3339", "2024-01-15T10:30:00Z", 2024, false},
		{"ISO without Z", "2024-01-15T10:30:00", 2024, false},
		{"Date only", "2024-01-15", 2024, false},
		{"Dot format", "2024.01.15", 2024, false},
		{"Empty string", "", 0, true},
		{"Invalid", "not a date", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseRUDate(tt.input)
			if tt.wantNil {
				if result != nil {
					t.Errorf("parseRUDate(%q) = %v, want nil", tt.input, result)
				}
			} else {
				if result == nil {
					t.Errorf("parseRUDate(%q) = nil, want year %d", tt.input, tt.wantYear)
				} else if result.Year() != tt.wantYear {
					t.Errorf("parseRUDate(%q).Year() = %d, want %d", tt.input, result.Year(), tt.wantYear)
				}
			}
		})
	}
}

func TestNormalizeRUNameserver(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ns1.example.ru", "ns1.example.ru"},
		{"NS1.EXAMPLE.RU", "ns1.example.ru"},
		{"ns1.example.ru.", "ns1.example.ru"},
		{"  ns1.example.ru  ", "ns1.example.ru"},
		{"ns1.example.ru 192.168.1.1", "ns1.example.ru"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeRUNameserver(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeRUNameserver(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func BenchmarkRUParser_Parse(b *testing.B) {
	p := NewRUParser()

	response := `domain:        EXAMPLE.RU
nserver:       ns1.example.ru.
nserver:       ns2.example.ru.
state:         REGISTERED, DELEGATED, VERIFIED
org:           Example Organization
registrar:     REGISTRAR-RU
created:       2000-01-15T00:00:00Z
paid-till:     2025-01-15T00:00:00Z
source:        TCI
`

	b.ResetTimer()
	for b.Loop() {
		_, _ = p.Parse(response, "example.ru")
	}
}
