// Package parsers provides TLD-specific WHOIS response parsers.
// These parsers understand the specific format of each registry's WHOIS output
// and can extract domain registration data with high confidence.
package parsers

import (
	"github.com/glimps-re/rdap-lookup/internal/whois"
)

// RegisterAll registers all built-in TLD parsers with the given registry.
func RegisterAll(registry *whois.ParserRegistry) {
	// Phase 1 parsers
	registry.Register(NewDEParser(), "de")
	registry.Register(NewCNParser(), "cn")
	registry.Register(NewRUParser(), "ru")
	registry.Register(NewAUParser(), "au", "com.au", "net.au", "org.au")

	// Phase 2 parsers
	registry.Register(NewEUParser(), "eu")
	registry.Register(NewITParser(), "it")
	registry.Register(NewESParser(), "es", "com.es", "org.es", "nom.es", "gob.es", "edu.es")
	registry.Register(NewJPParser(), "jp", "co.jp", "or.jp", "ne.jp", "ac.jp", "ad.jp", "ed.jp", "go.jp", "gr.jp", "lg.jp")
}

// RegisterWithDefaults registers all built-in parsers with the default registry.
func RegisterWithDefaults() {
	RegisterAll(whois.DefaultRegistry)
}
