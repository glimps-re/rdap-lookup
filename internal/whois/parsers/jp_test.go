package parsers

import (
	"errors"
	"testing"

	"github.com/glimps-re/rdap-lookup/internal/whois"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestJPParser_Name(t *testing.T) {
	p := NewJPParser()
	if p.Name() != "jp" {
		t.Errorf("Name() = %q, want jp", p.Name())
	}
}

func TestJPParser_SupportsTLD(t *testing.T) {
	p := NewJPParser()

	tests := []struct {
		tld      string
		expected bool
	}{
		{"jp", true},
		{"JP", true},
		{"co.jp", true},
		{"or.jp", true},
		{"ne.jp", true},
		{"ac.jp", true},
		{"go.jp", true},
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

func TestJPParser_Parse(t *testing.T) {
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
			response: `[ JPRS database provides information on network administration. Its use is    ]
[ restricted to network administration purposes.                              ]

Domain Information: [ドメイン情報]
a. [ドメイン名]                 EXAMPLE.JP
g. [Organization]               Example Corporation
m. [登録担当者]                 XX12345JP
n. [技術連絡担当者]             YY67890JP
p. [ネームサーバ]               ns1.example.jp
p. [ネームサーバ]               ns2.example.jp
[状態]                          Active
[登録年月日]                    2000/01/15
[最終更新]                      2024/01/15 10:30:00 (JST)
`,
			domain: "example.jp",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName:  "example.jp",
					Status:      []string{"Active"},
					Nameservers: []string{"ns1.example.jp", "ns2.example.jp"},
					CreatedDate: utc(2000, 1, 15, 0, 0, 0),
					UpdatedDate: utc(2024, 1, 15, 10, 30, 0),
					Registrant: &whois.ParsedEntity{
						Handle:       "XX12345JP",
						Organization: "Example Corporation",
					},
					TechContact: &whois.ParsedEntity{Handle: "YY67890JP"},
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "jp",
			},
		},
		{
			name:     "not found: No match",
			response: "No match!!\n",
			domain:   "notfound.jp",
			want: &whois.ParseResult{
				Domain:     &whois.ParsedDomain{DomainName: "notfound.jp"},
				Confidence: whois.ConfidenceLow,
				ParserName: "jp",
				Errors:     []string{"domain not found"},
				NotFound:   true,
			},
			wantErr: whois.ErrDomainNotFound,
		},
		{
			name:     "not found: Not found",
			response: "Not found\n",
			domain:   "notfound.jp",
			want: &whois.ParseResult{
				Domain:     &whois.ParsedDomain{DomainName: "notfound.jp"},
				Confidence: whois.ConfidenceLow,
				ParserName: "jp",
				Errors:     []string{"domain not found"},
				NotFound:   true,
			},
			wantErr: whois.ErrDomainNotFound,
		},
		{
			name:     "not found: No entries",
			response: "No entries found\n",
			domain:   "notfound.jp",
			want: &whois.ParseResult{
				Domain:     &whois.ParsedDomain{DomainName: "notfound.jp"},
				Confidence: whois.ConfidenceLow,
				ParserName: "jp",
				Errors:     []string{"domain not found"},
				NotFound:   true,
			},
			wantErr: whois.ErrDomainNotFound,
		},
		{
			name:   "empty response",
			domain: "example.jp",
			want: &whois.ParseResult{
				Domain:     &whois.ParsedDomain{DomainName: "example.jp"},
				Confidence: whois.ConfidenceHigh,
				ParserName: "jp",
			},
			wantErr: whois.ErrNoRegistrationData,
		},
		{
			name:     "DNSSEC: signing key present",
			response: "a. [ドメイン名]                 EXAMPLE.JP\ns. [署名鍵]                     12345 3 13 ABC123...\n",
			domain:   "example.jp",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName:   "example.jp",
					DNSSECSigned: ptr(true),
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "jp",
			},
			wantErr: whois.ErrNoRegistrationData,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := NewJPParser()

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

func TestParseJPDate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantYear int
		wantNil  bool
	}{
		{"JPRS format with time", "2024/01/15 10:30:00", 2024, false},
		{"JPRS format date only", "2024/01/15", 2024, false},
		{"With JST suffix", "2024/01/15 10:30:00 (JST)", 2024, false},
		{"ISO format", "2024-01-15", 2024, false},
		{"Empty string", "", 0, true},
		{"Invalid", "not a date", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseJPDate(tt.input)
			if tt.wantNil {
				if result != nil {
					t.Errorf("parseJPDate(%q) = %v, want nil", tt.input, result)
				}
			} else {
				if result == nil {
					t.Errorf("parseJPDate(%q) = nil, want year %d", tt.input, tt.wantYear)
				} else if result.Year() != tt.wantYear {
					t.Errorf("parseJPDate(%q).Year() = %d, want %d", tt.input, result.Year(), tt.wantYear)
				}
			}
		})
	}
}

func TestNormalizeJPNameserver(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ns1.example.jp", "ns1.example.jp"},
		{"NS1.EXAMPLE.JP", "ns1.example.jp"},
		{"ns1.example.jp.", "ns1.example.jp"},
		{"ns1.example.jp 192.168.1.1", "ns1.example.jp"},
		{"example", ""}, // No dot
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeJPNameserver(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeJPNameserver(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func BenchmarkJPParser_Parse(b *testing.B) {
	p := NewJPParser()

	response := `a. [ドメイン名]                 EXAMPLE.JP
g. [Organization]               Example Corporation
p. [ネームサーバ]               ns1.example.jp
p. [ネームサーバ]               ns2.example.jp
[状態]                          Active
[登録年月日]                    2000/01/15
`

	b.ResetTimer()
	for b.Loop() {
		_, _ = p.Parse(response, "example.jp")
	}
}
