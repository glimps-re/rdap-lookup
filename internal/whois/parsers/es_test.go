package parsers

import (
	"errors"
	"testing"

	"github.com/glimps-re/rdap-lookup/internal/whois"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestESParser_Name(t *testing.T) {
	p := NewESParser()
	if p.Name() != "es" {
		t.Errorf("Name() = %q, want es", p.Name())
	}
}

func TestESParser_SupportsTLD(t *testing.T) {
	p := NewESParser()

	tests := []struct {
		tld      string
		expected bool
	}{
		{"es", true},
		{"ES", true},
		{"com.es", true},
		{"org.es", true},
		{"nom.es", true},
		{"gob.es", true},
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

func TestESParser_Parse(t *testing.T) {
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
			response: `Nombre de dominio / Domain name: example.es

INFORMACIÓN DEL TITULAR / HOLDER INFORMATION
Tipo de identificación / Identification Type: NIF/NIE
Identificación / Identification: ***
Nombre / Name: ***

INFORMACIÓN DEL AGENTE REGISTRADOR / REGISTRAR INFORMATION
Nombre / Name: Example Registrar, S.L.
URL: https://www.example-registrar.es

INFORMACIÓN TÉCNICA DEL DOMINIO / TECHNICAL INFORMATION
Servidores DNS / DNS Servers:
   ns1.example.es
   ns2.example.es

Estado del dominio / Domain Status: activo/active
Fecha de creación / Creation Date: 01/01/2000
Fecha de caducidad / Expiration Date: 01/01/2025
`,
			domain: "example.es",
			want: &whois.ParseResult{
				Domain: &whois.ParsedDomain{
					DomainName:     "example.es",
					Status:         []string{"activo/active"},
					Nameservers:    []string{"ns1.example.es", "ns2.example.es"},
					CreatedDate:    utc(2000, 1, 1, 0, 0, 0),
					ExpirationDate: utc(2025, 1, 1, 0, 0, 0),
					Registrar: &whois.ParsedEntity{
						Name:    "Example Registrar, S.L.",
						Address: "https://www.example-registrar.es",
					},
					Registrant: &whois.ParsedEntity{},
				},
				Confidence: whois.ConfidenceHigh,
				ParserName: "es",
			},
		},
		{
			name:     "not found: No existe",
			response: "El dominio no existe\n",
			domain:   "notfound.es",
			want: &whois.ParseResult{
				Domain:     &whois.ParsedDomain{DomainName: "notfound.es"},
				Confidence: whois.ConfidenceLow,
				ParserName: "es",
				Errors:     []string{"domain not found"},
				NotFound:   true,
			},
			wantErr: whois.ErrDomainNotFound,
		},
		{
			name:     "not found: Does not exist",
			response: "Domain does not exist\n",
			domain:   "notfound.es",
			want: &whois.ParseResult{
				Domain:     &whois.ParsedDomain{DomainName: "notfound.es"},
				Confidence: whois.ConfidenceLow,
				ParserName: "es",
				Errors:     []string{"domain not found"},
				NotFound:   true,
			},
			wantErr: whois.ErrDomainNotFound,
		},
		{
			name:     "not found: Not found",
			response: "Not found\n",
			domain:   "notfound.es",
			want: &whois.ParseResult{
				Domain:     &whois.ParsedDomain{DomainName: "notfound.es"},
				Confidence: whois.ConfidenceLow,
				ParserName: "es",
				Errors:     []string{"domain not found"},
				NotFound:   true,
			},
			wantErr: whois.ErrDomainNotFound,
		},
		{
			name:     "not found: No match",
			response: "No match for domain\n",
			domain:   "notfound.es",
			want: &whois.ParseResult{
				Domain:     &whois.ParsedDomain{DomainName: "notfound.es"},
				Confidence: whois.ConfidenceLow,
				ParserName: "es",
				Errors:     []string{"domain not found"},
				NotFound:   true,
			},
			wantErr: whois.ErrDomainNotFound,
		},
		{
			name:   "empty response",
			domain: "example.es",
			want: &whois.ParseResult{
				Domain:     &whois.ParsedDomain{DomainName: "example.es"},
				Confidence: whois.ConfidenceHigh,
				ParserName: "es",
			},
			wantErr: whois.ErrNoRegistrationData,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := NewESParser()

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

func TestParseESDate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantYear int
		wantNil  bool
	}{
		{"DD/MM/YYYY", "01/01/2000", 2000, false},
		{"D/M/YYYY", "1/1/2000", 2000, false},
		{"YYYY-MM-DD", "2024-01-15", 2024, false},
		{"Empty string", "", 0, true},
		{"Invalid", "not a date", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseESDate(tt.input)
			if tt.wantNil {
				if result != nil {
					t.Errorf("parseESDate(%q) = %v, want nil", tt.input, result)
				}
			} else {
				if result == nil {
					t.Errorf("parseESDate(%q) = nil, want year %d", tt.input, tt.wantYear)
				} else if result.Year() != tt.wantYear {
					t.Errorf("parseESDate(%q).Year() = %d, want %d", tt.input, result.Year(), tt.wantYear)
				}
			}
		})
	}
}

func TestNormalizeESNameserver(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ns1.example.es", "ns1.example.es"},
		{"NS1.EXAMPLE.ES", "ns1.example.es"},
		{"ns1.example.es.", "ns1.example.es"},
		{"example", ""}, // No dot
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeESNameserver(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeESNameserver(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func BenchmarkESParser_Parse(b *testing.B) {
	p := NewESParser()

	response := `Nombre de dominio / Domain name: example.es
INFORMACIÓN DEL AGENTE REGISTRADOR / REGISTRAR INFORMATION
Nombre / Name: Example Registrar, S.L.
INFORMACIÓN TÉCNICA DEL DOMINIO / TECHNICAL INFORMATION
Servidores DNS / DNS Servers:
   ns1.example.es
   ns2.example.es
Fecha de creación / Creation Date: 01/01/2000
Fecha de caducidad / Expiration Date: 01/01/2025
`

	b.ResetTimer()
	for b.Loop() {
		_, _ = p.Parse(response, "example.es")
	}
}
