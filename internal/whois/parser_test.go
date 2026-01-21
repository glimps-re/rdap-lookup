package whois

import (
	"testing"
)

func TestParserRegistry_GetParser(t *testing.T) {
	registry := NewParserRegistry()

	// Should return generic parser for unregistered TLD
	parser := registry.GetParser("com")
	if parser.Name() != "generic" {
		t.Errorf("GetParser(com) = %q, want generic", parser.Name())
	}
}

func TestParserRegistry_Register(t *testing.T) {
	registry := NewParserRegistry()

	// Create a mock parser
	mockParser := &mockParser{name: "test-parser"}

	// Register for .test TLD
	registry.Register(mockParser, "test", ".test2")

	// Should return mock parser for registered TLDs
	parser := registry.GetParser("test")
	if parser.Name() != "test-parser" {
		t.Errorf("GetParser(test) = %q, want test-parser", parser.Name())
	}

	parser = registry.GetParser(".test2")
	if parser.Name() != "test-parser" {
		t.Errorf("GetParser(.test2) = %q, want test-parser", parser.Name())
	}

	// Should still return generic for unregistered TLD
	parser = registry.GetParser("other")
	if parser.Name() != "generic" {
		t.Errorf("GetParser(other) = %q, want generic", parser.Name())
	}
}

func TestParserRegistry_RegisteredTLDs(t *testing.T) {
	registry := NewParserRegistry()

	mockParser := &mockParser{name: "test"}
	registry.Register(mockParser, "com", "net", "org")

	tlds := registry.RegisteredTLDs()
	if len(tlds) != 3 {
		t.Errorf("RegisteredTLDs() returned %d TLDs, want 3", len(tlds))
	}

	// Check all TLDs are present
	tldMap := make(map[string]bool)
	for _, tld := range tlds {
		tldMap[tld] = true
	}

	for _, expected := range []string{"com", "net", "org"} {
		if !tldMap[expected] {
			t.Errorf("RegisteredTLDs() missing %q", expected)
		}
	}
}

func TestParserRegistry_Parse(t *testing.T) {
	registry := NewParserRegistry()

	response := `Domain Name: example.com
Status: active
Name Server: ns1.example.com
`
	result, err := registry.Parse(response, "example.com")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	if result.ParserName != "generic" {
		t.Errorf("ParserName = %q, want generic", result.ParserName)
	}
}

func TestFieldExtractor_Extract(t *testing.T) {
	extractor := newFieldExtractor("Domain Name", "domain")

	tests := []struct {
		name     string
		response string
		expected string
	}{
		{
			name:     "standard format",
			response: "Domain Name: example.com",
			expected: "example.com",
		},
		{
			name:     "with extra whitespace",
			response: "Domain Name:    example.com   ",
			expected: "example.com",
		},
		{
			name: "case insensitive",
			response: `domain name: example.com
DOMAIN NAME: other.com`,
			expected: "example.com",
		},
		{
			name:     "not found",
			response: "Status: active",
			expected: "",
		},
		{
			name: "with comment lines",
			response: `% WHOIS data
# Comment
Domain Name: example.com`,
			expected: "example.com",
		},
		{
			name:     "empty value",
			response: "Domain Name:",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractor.Extract(tt.response)
			if result != tt.expected {
				t.Errorf("Extract() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestFieldExtractor_ExtractAll(t *testing.T) {
	extractor := newFieldExtractor("Name Server", "Nameserver")

	tests := []struct {
		name     string
		response string
		expected []string
	}{
		{
			name: "multiple nameservers",
			response: `Name Server: ns1.example.com
Name Server: ns2.example.com
Name Server: ns3.example.com`,
			expected: []string{"ns1.example.com", "ns2.example.com", "ns3.example.com"},
		},
		{
			name:     "single nameserver",
			response: "Name Server: ns1.example.com",
			expected: []string{"ns1.example.com"},
		},
		{
			name:     "no nameservers",
			response: "Domain Name: example.com",
			expected: nil,
		},
		{
			name: "mixed case patterns",
			response: `Name Server: ns1.example.com
NAMESERVER: ns2.example.com`,
			expected: []string{"ns1.example.com", "ns2.example.com"},
		},
		{
			name: "duplicates removed",
			response: `Name Server: ns1.example.com
Name Server: ns1.example.com
Name Server: ns2.example.com`,
			expected: []string{"ns1.example.com", "ns2.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractor.ExtractAll(tt.response)
			if len(result) != len(tt.expected) {
				t.Errorf("ExtractAll() returned %d items, want %d", len(result), len(tt.expected))
				return
			}
			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("ExtractAll()[%d] = %q, want %q", i, v, tt.expected[i])
				}
			}
		})
	}
}

func TestDefaultRegistry(t *testing.T) {
	// Test that DefaultRegistry is properly initialized
	if DefaultRegistry == nil {
		t.Fatal("DefaultRegistry should not be nil")
	}

	// Test Parse function uses DefaultRegistry
	response := "Domain Name: test.com"
	result, err := Parse(response, "test.com")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	if result.Domain == nil {
		t.Error("result.Domain should not be nil")
	}
}

// mockParser is a test helper parser.
type mockParser struct {
	name string
}

func (p *mockParser) Parse(response, domain string) (*ParseResult, error) {
	return &ParseResult{
		Domain:     &ParsedDomain{DomainName: domain},
		Confidence: ConfidenceHigh,
		ParserName: p.name,
	}, nil
}

func (p *mockParser) Name() string {
	return p.name
}

func (p *mockParser) SupportsTLD(_ string) bool {
	return true
}
