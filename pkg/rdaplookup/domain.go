package rdaplookup

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// NormalizeDomain extracts the registrable domain (eTLD+1) from a given domain name.
// For example:
//   - "www.example.com" -> "example.com"
//   - "api.test.example.co.uk" -> "example.co.uk"
//   - "example.com" -> "example.com"
//   - "co.uk" -> "" (returns empty for public suffixes)
//
// This is useful for RDAP lookups since subdomains are not separately registered.
func NormalizeDomain(name string) string {
	// Normalize input
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.TrimSuffix(name, ".")

	if name == "" {
		return ""
	}

	// Use publicsuffix to get the effective TLD+1 (registrable domain)
	domain, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		// If extraction fails (e.g., the input is a public suffix itself),
		// return the original name - let the server handle validation
		return name
	}

	return domain
}

// IsPublicSuffix returns true if the domain is a public suffix (e.g., "com", "co.uk").
// Public suffixes cannot be looked up via RDAP as they are not registrable.
func IsPublicSuffix(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.TrimSuffix(name, ".")

	if name == "" {
		return false
	}

	suffix, _ := publicsuffix.PublicSuffix(name)
	return suffix == name
}
