package whois

import (
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestWHOISError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *WHOISError
		expected string
	}{
		{
			name: "with server",
			err: &WHOISError{
				Op:     "query",
				Server: "whois.example.com",
				Err:    errors.New("connection refused"),
			},
			expected: "query whois.example.com: connection refused",
		},
		{
			name: "without server",
			err: &WHOISError{
				Op:  "parse",
				Err: errors.New("invalid format"),
			},
			expected: "parse: invalid format",
		},
		{
			name: "empty server",
			err: &WHOISError{
				Op:     "discover",
				Server: "",
				Err:    errors.New("timeout"),
			},
			expected: "discover: timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.expected {
				t.Errorf("WHOISError.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestWHOISError_Unwrap(t *testing.T) {
	underlying := errors.New("underlying error")
	err := &WHOISError{
		Op:     "query",
		Server: "whois.example.com",
		Err:    underlying,
	}

	unwrapped := err.Unwrap()
	if !errors.Is(unwrapped, underlying) {
		t.Errorf("WHOISError.Unwrap() = %v, want %v", unwrapped, underlying)
	}

	// Test that errors.Is works through the wrapper
	if !errors.Is(err, underlying) {
		t.Error("errors.Is should return true for underlying error")
	}
}

func TestConfidence_Values(t *testing.T) {
	// Verify confidence constants
	if ConfidenceHigh != "high" {
		t.Errorf("ConfidenceHigh = %q, want %q", ConfidenceHigh, "high")
	}
	if ConfidenceLow != "low" {
		t.Errorf("ConfidenceLow = %q, want %q", ConfidenceLow, "low")
	}
}

func TestDataSource_Values(t *testing.T) {
	// Verify data source constants
	if DataSourceRDAP != "rdap" {
		t.Errorf("DataSourceRDAP = %q, want %q", DataSourceRDAP, "rdap")
	}
	if DataSourceWHOIS != "whois" {
		t.Errorf("DataSourceWHOIS = %q, want %q", DataSourceWHOIS, "whois")
	}
}

func TestParsedDomain_Initialization(t *testing.T) {
	// Test that ParsedDomain can be properly initialized
	pd := &ParsedDomain{
		DomainName:  "example.com",
		WHOISServer: "whois.example.com",
		Status:      []string{"active"},
		Nameservers: []string{"ns1.example.com", "ns2.example.com"},
	}

	if pd.DomainName != "example.com" {
		t.Errorf("DomainName = %q, want %q", pd.DomainName, "example.com")
	}
	if pd.WHOISServer != "whois.example.com" {
		t.Errorf("WHOISServer = %q, want %q", pd.WHOISServer, "whois.example.com")
	}
	if len(pd.Status) != 1 {
		t.Errorf("len(Status) = %d, want 1", len(pd.Status))
	}
	if len(pd.Nameservers) != 2 {
		t.Errorf("len(Nameservers) = %d, want 2", len(pd.Nameservers))
	}
}

func TestParsedEntity_Initialization(t *testing.T) {
	// Test that ParsedEntity can be properly initialized
	pe := &ParsedEntity{
		Name:         "Test Organization",
		Organization: "Test Org Inc.",
		Email:        "admin@example.com",
		Phone:        "+1.5555551234",
		Country:      "US",
	}

	if pe.Name != "Test Organization" {
		t.Errorf("Name = %q, want %q", pe.Name, "Test Organization")
	}
	if pe.Country != "US" {
		t.Errorf("Country = %q, want %q", pe.Country, "US")
	}
}

func TestParseResult_Initialization(t *testing.T) {
	// Test that ParseResult can be properly initialized
	pr := &ParseResult{
		Domain: &ParsedDomain{
			DomainName: "example.com",
		},
		Confidence: ConfidenceHigh,
		ParserName: "generic",
		Errors:     []string{"minor warning"},
	}

	if pr.Domain.DomainName != "example.com" {
		t.Errorf("Domain.DomainName = %q, want %q", pr.Domain.DomainName, "example.com")
	}
	if pr.Confidence != ConfidenceHigh {
		t.Errorf("Confidence = %q, want %q", pr.Confidence, ConfidenceHigh)
	}
	if pr.ParserName != "generic" {
		t.Errorf("ParserName = %q, want %q", pr.ParserName, "generic")
	}
	if len(pr.Errors) != 1 {
		t.Errorf("len(Errors) = %d, want 1", len(pr.Errors))
	}
}

func TestQueryResult_Initialization(t *testing.T) {
	// Test that QueryResult can be properly initialized
	qr := &QueryResult{
		Server:   "whois.example.com",
		Response: "Domain Name: example.com\n",
		Cached:   true,
	}

	if qr.Server != "whois.example.com" {
		t.Errorf("Server = %q, want %q", qr.Server, "whois.example.com")
	}
	if !qr.Cached {
		t.Error("Cached should be true")
	}
}

func TestParsedDomain_HasData(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		domain *ParsedDomain
		want   bool
	}{
		{
			name: "nil domain",
		},
		{
			name: "name and status only",
			domain: &ParsedDomain{
				DomainName: "free.de",
				Status:     []string{"free"},
			},
		},
		{
			name: "empty entity allocated on a section header",
			domain: &ParsedDomain{
				DomainName: "free.de",
				Registrant: &ParsedEntity{},
			},
		},
		{
			name:   "creation date",
			domain: &ParsedDomain{CreatedDate: utc(2020, 1, 1, 0, 0, 0)},
			want:   true,
		},
		{
			name:   "update date",
			domain: &ParsedDomain{UpdatedDate: utc(2024, 1, 15, 0, 0, 0)},
			want:   true,
		},
		{
			name:   "expiration date",
			domain: &ParsedDomain{ExpirationDate: utc(2030, 1, 1, 0, 0, 0)},
			want:   true,
		},
		{
			name:   "nameserver",
			domain: &ParsedDomain{Nameservers: []string{"ns1.taken.de"}},
			want:   true,
		},
		{
			name: "filled registrant",
			domain: &ParsedDomain{
				Registrant: &ParsedEntity{Name: "Taken GmbH"},
			},
			want: true,
		},
		{
			name: "filled admin contact",
			domain: &ParsedDomain{
				AdminContact: &ParsedEntity{Email: "admin@taken.de"},
			},
			want: true,
		},
		{
			name: "filled tech contact",
			domain: &ParsedDomain{
				TechContact: &ParsedEntity{Handle: "TECH-1"},
			},
			want: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.domain.HasData(); got != tc.want {
				t.Errorf("HasData() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseResult_MarkNotFound(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		domain        *ParsedDomain
		phraseMatched bool
		want          *ParseResult
	}{
		{
			name: "phrase without data",
			domain: &ParsedDomain{
				DomainName: "free.de",
				Status:     []string{"free"},
			},
			phraseMatched: true,
			want: &ParseResult{
				Domain: &ParsedDomain{
					DomainName: "free.de",
					Status:     []string{"free"},
				},
				Confidence: ConfidenceLow,
				Errors:     []string{"domain not found"},
				NotFound:   true,
			},
		},
		{
			name: "phrase with data",
			domain: &ParsedDomain{
				DomainName:  "taken.de",
				Nameservers: []string{"ns1.taken.de"},
			},
			phraseMatched: true,
			want: &ParseResult{
				Domain: &ParsedDomain{
					DomainName:  "taken.de",
					Nameservers: []string{"ns1.taken.de"},
				},
				Confidence: ConfidenceHigh,
			},
		},
		{
			name:   "no phrase",
			domain: &ParsedDomain{DomainName: "unknown.de"},
			want: &ParseResult{
				Domain:     &ParsedDomain{DomainName: "unknown.de"},
				Confidence: ConfidenceHigh,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := &ParseResult{
				Domain:     tc.domain,
				Confidence: ConfidenceHigh,
			}

			got.MarkNotFound(tc.phraseMatched, "domain not found")

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ParseResult mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParseResult_Err(t *testing.T) {
	t.Parallel()
	created := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		result  *ParseResult
		wantErr error
	}{
		{
			name: "not found",
			result: &ParseResult{
				Domain:   &ParsedDomain{DomainName: "free.de"},
				NotFound: true,
			},
			wantErr: ErrDomainNotFound,
		},
		{
			name: "nothing extracted",
			result: &ParseResult{
				Domain: &ParsedDomain{
					DomainName: "odd.xx",
					Status:     []string{"active"},
				},
			},
			wantErr: ErrNoRegistrationData,
		},
		{
			name:    "nil domain",
			result:  &ParseResult{},
			wantErr: ErrNoRegistrationData,
		},
		{
			name: "registered",
			result: &ParseResult{
				Domain: &ParsedDomain{
					DomainName:  "taken.xx",
					CreatedDate: &created,
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := tc.result.Err(); !errors.Is(err, tc.wantErr) {
				t.Errorf("Err() = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func utc(year int, month time.Month, day, hour, minute, second int) *time.Time {
	return new(time.Date(year, month, day, hour, minute, second, 0, time.UTC))
}
