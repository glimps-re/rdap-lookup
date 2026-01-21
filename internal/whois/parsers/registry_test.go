package parsers

import (
	"testing"

	"github.com/glimps-re/rdap-lookup/internal/whois"
)

func TestRegisterAll(t *testing.T) {
	registry := whois.NewParserRegistry()
	RegisterAll(registry)

	// Verify all expected TLDs are registered
	expectedTLDs := []string{
		// Phase 1
		"de", "cn", "ru", "au", "com.au", "net.au", "org.au",
		// Phase 2
		"eu", "it", "es", "com.es", "jp", "co.jp",
	}

	for _, tld := range expectedTLDs {
		parser := registry.GetParser(tld)
		if parser.Name() == "generic" {
			t.Errorf("GetParser(%q) returned generic parser, expected specific parser", tld)
		}
	}
}

func TestRegisterAll_DEParser(t *testing.T) {
	registry := whois.NewParserRegistry()
	RegisterAll(registry)

	parser := registry.GetParser("de")
	if parser.Name() != "de" {
		t.Errorf("GetParser(de) = %q, want de", parser.Name())
	}
}

func TestRegisterAll_CNParser(t *testing.T) {
	registry := whois.NewParserRegistry()
	RegisterAll(registry)

	parser := registry.GetParser("cn")
	if parser.Name() != "cn" {
		t.Errorf("GetParser(cn) = %q, want cn", parser.Name())
	}
}

func TestRegisterAll_RUParser(t *testing.T) {
	registry := whois.NewParserRegistry()
	RegisterAll(registry)

	parser := registry.GetParser("ru")
	if parser.Name() != "ru" {
		t.Errorf("GetParser(ru) = %q, want ru", parser.Name())
	}
}

func TestRegisterAll_AUParser(t *testing.T) {
	registry := whois.NewParserRegistry()
	RegisterAll(registry)

	tests := []struct {
		tld          string
		expectedName string
	}{
		{"au", "au"},
		{"com.au", "au"},
		{"net.au", "au"},
		{"org.au", "au"},
	}

	for _, tt := range tests {
		t.Run(tt.tld, func(t *testing.T) {
			parser := registry.GetParser(tt.tld)
			if parser.Name() != tt.expectedName {
				t.Errorf("GetParser(%q) = %q, want %q", tt.tld, parser.Name(), tt.expectedName)
			}
		})
	}
}

func TestRegisterAll_UnknownTLD(t *testing.T) {
	registry := whois.NewParserRegistry()
	RegisterAll(registry)

	// Unknown TLDs should fall back to generic parser
	unknownTLDs := []string{"com", "net", "org", "xyz", "unknown"}

	for _, tld := range unknownTLDs {
		parser := registry.GetParser(tld)
		if parser.Name() != "generic" {
			t.Errorf("GetParser(%q) = %q, want generic", tld, parser.Name())
		}
	}
}

func TestRegisterWithDefaults(t *testing.T) {
	// Save original default registry
	originalRegistry := whois.DefaultRegistry

	// Create a new registry and set as default
	whois.DefaultRegistry = whois.NewParserRegistry()

	// Register with defaults
	RegisterWithDefaults()

	// Verify parsers are registered
	parser := whois.DefaultRegistry.GetParser("de")
	if parser.Name() != "de" {
		t.Errorf("DefaultRegistry.GetParser(de) = %q, want de", parser.Name())
	}

	// Restore original registry
	whois.DefaultRegistry = originalRegistry
}

func TestRegisteredTLDs(t *testing.T) {
	registry := whois.NewParserRegistry()
	RegisterAll(registry)

	tlds := registry.RegisteredTLDs()

	// Should have at least 20 TLDs registered (Phase 1 + Phase 2 with SLDs)
	if len(tlds) < 20 {
		t.Errorf("RegisteredTLDs() returned %d TLDs, want at least 20", len(tlds))
	}

	// Verify specific TLDs are present
	tldMap := make(map[string]bool)
	for _, tld := range tlds {
		tldMap[tld] = true
	}

	requiredTLDs := []string{
		// Phase 1
		"de", "cn", "ru", "au", "com.au", "net.au", "org.au",
		// Phase 2
		"eu", "it", "es", "jp",
	}
	for _, required := range requiredTLDs {
		if !tldMap[required] {
			t.Errorf("RegisteredTLDs() missing %q", required)
		}
	}
}

func TestParsersParseCorrectly(t *testing.T) {
	registry := whois.NewParserRegistry()
	RegisterAll(registry)

	tests := []struct {
		tld      string
		response string
		domain   string
		expected string
	}{
		// Phase 1
		{
			tld:      "de",
			response: "Domain: test.de\nStatus: connect\n",
			domain:   "test.de",
			expected: "test.de",
		},
		{
			tld:      "cn",
			response: "Domain Name: test.cn\nDomain Status: ok\n",
			domain:   "test.cn",
			expected: "test.cn",
		},
		{
			tld:      "ru",
			response: "domain:        TEST.RU\nstate:         REGISTERED\n",
			domain:   "test.ru",
			expected: "test.ru",
		},
		{
			tld:      "com.au",
			response: "Domain Name: test.com.au\nStatus: ok\n",
			domain:   "test.com.au",
			expected: "test.com.au",
		},
		// Phase 2
		{
			tld:      "eu",
			response: "Domain: test.eu\nStatus: REGISTERED\n",
			domain:   "test.eu",
			expected: "test.eu",
		},
		{
			tld:      "it",
			response: "Domain:             test.it\nStatus:             ok\n",
			domain:   "test.it",
			expected: "test.it",
		},
		{
			tld:      "es",
			response: "Nombre de dominio / Domain name: test.es\nEstado / Status: activo\n",
			domain:   "test.es",
			expected: "test.es",
		},
		{
			tld:      "jp",
			response: "a. [ドメイン名]                 TEST.JP\n[状態]                          Active\n",
			domain:   "test.jp",
			expected: "test.jp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.tld, func(t *testing.T) {
			parser := registry.GetParser(tt.tld)
			result, err := parser.Parse(tt.response, tt.domain)
			if err != nil {
				t.Fatalf("Parse error = %v", err)
			}

			if result.Domain.DomainName != tt.expected {
				t.Errorf("DomainName = %q, want %q", result.Domain.DomainName, tt.expected)
			}

			if result.Confidence != "high" {
				t.Errorf("Confidence = %q, want high", result.Confidence)
			}
		})
	}
}
