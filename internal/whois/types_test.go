package whois

import (
	"errors"
	"testing"
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
