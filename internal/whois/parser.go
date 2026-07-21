package whois

import "strings"

// Parser defines the interface for WHOIS response parsers.
type Parser interface {
	// Parse parses a WHOIS response and returns the extracted domain data.
	Parse(response string, domain string) (*ParseResult, error)
	// Name returns the parser name.
	Name() string
	// SupportsTLD returns true if this parser supports the given TLD.
	SupportsTLD(tld string) bool
}

// ParserRegistry manages WHOIS parsers for different TLDs.
type ParserRegistry struct {
	// parsers maps TLD to parser.
	parsers map[string]Parser
	// generic is the fallback generic parser.
	generic Parser
}

// NewParserRegistry creates a new parser registry with the generic parser as fallback.
func NewParserRegistry() *ParserRegistry {
	return &ParserRegistry{
		parsers: make(map[string]Parser),
		generic: NewGenericParser(),
	}
}

// Register registers a parser for the given TLDs.
func (r *ParserRegistry) Register(parser Parser, tlds ...string) {
	for _, tld := range tlds {
		r.parsers[normalizeTLD(tld)] = parser
	}
}

// GetParser returns the parser for the given TLD.
// If no specific parser is registered, returns the generic parser.
func (r *ParserRegistry) GetParser(tld string) Parser {
	tld = normalizeTLD(tld)
	if parser, ok := r.parsers[tld]; ok {
		return parser
	}
	return r.generic
}

// Parse parses a WHOIS response for the given domain.
// It automatically selects the appropriate parser based on the TLD.
func (r *ParserRegistry) Parse(response, domain string) (*ParseResult, error) {
	tld := ExtractTLD(domain)
	parser := r.GetParser(tld)
	return parser.Parse(response, domain)
}

// RegisteredTLDs returns the list of TLDs with registered parsers.
func (r *ParserRegistry) RegisteredTLDs() []string {
	tlds := make([]string, 0, len(r.parsers))
	for tld := range r.parsers {
		tlds = append(tlds, tld)
	}
	return tlds
}

// DefaultRegistry is the default parser registry with all built-in parsers.
var DefaultRegistry = NewParserRegistry()

// RegisterParser registers a parser with the default registry.
func RegisterParser(parser Parser, tlds ...string) {
	DefaultRegistry.Register(parser, tlds...)
}

// Parse parses a WHOIS response using the default registry.
func Parse(response, domain string) (*ParseResult, error) {
	return DefaultRegistry.Parse(response, domain)
}

// fieldExtractor extracts values from WHOIS responses using pattern matching.
type fieldExtractor struct {
	// patterns are the field names to look for (e.g., "Domain Name", "domain")
	patterns []string
}

// newFieldExtractor creates a new field extractor with the given patterns.
func newFieldExtractor(patterns ...string) *fieldExtractor {
	return &fieldExtractor{patterns: patterns}
}

// Extract extracts the value for this field from the WHOIS response.
// Returns empty string if not found.
func (f *fieldExtractor) Extract(response string) string {
	lines := strings.SplitSeq(response, "\n")
	for line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}

		for _, pattern := range f.patterns {
			// Try "Pattern: Value" format
			if idx := strings.Index(strings.ToLower(line), strings.ToLower(pattern)+":"); idx != -1 {
				// Find the colon position
				_, value, found := strings.Cut(line, ":")
				if found {
					value = strings.TrimSpace(value)
					if value != "" {
						return value
					}
				}
				_ = idx // silence unused warning
			}
		}
	}
	return ""
}

// ExtractAll extracts all values for this field from the WHOIS response.
// Useful for fields that can appear multiple times (e.g., nameservers).
func (f *fieldExtractor) ExtractAll(response string) []string {
	var values []string
	seen := make(map[string]bool)

	lines := strings.SplitSeq(response, "\n")
	for line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}

		for _, pattern := range f.patterns {
			if idx := strings.Index(strings.ToLower(line), strings.ToLower(pattern)+":"); idx != -1 {
				_, value, found := strings.Cut(line, ":")
				if found {
					value = strings.TrimSpace(value)
					if value != "" && !seen[value] {
						values = append(values, value)
						seen[value] = true
					}
				}
				_ = idx // silence unused warning
			}
		}
	}
	return values
}
