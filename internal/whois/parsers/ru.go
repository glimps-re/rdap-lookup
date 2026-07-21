package parsers

import (
	"strings"
	"time"

	"github.com/glimps-re/rdap-lookup/internal/whois"
)

// RUParser parses WHOIS responses from TCINET (.ru registry).
// TCINET uses a specific format with lowercase field names.
//
// Example format:
//
//	domain:        EXAMPLE.RU
//	nserver:       ns1.example.ru.
//	nserver:       ns2.example.ru.
//	state:         REGISTERED, DELEGATED, VERIFIED
//	org:           Example Organization
//	registrar:     REGISTRAR-RU
//	admin-contact: https://whois.tcinet.ru
//	created:       2000-01-01T00:00:00Z
//	paid-till:     2025-01-01T00:00:00Z
//	free-date:     2025-02-01
//	source:        TCI
type RUParser struct{}

// NewRUParser creates a new .ru WHOIS parser.
func NewRUParser() *RUParser {
	return &RUParser{}
}

// Name returns the parser name.
func (p *RUParser) Name() string {
	return "ru"
}

// SupportsTLD returns true if this parser supports the given TLD.
func (p *RUParser) SupportsTLD(tld string) bool {
	tld = strings.ToLower(tld)
	return tld == "ru" || tld == "su" || tld == "rf" || tld == "xn--p1ai"
}

// Parse parses a TCINET WHOIS response.
func (p *RUParser) Parse(response string, domain string) (*whois.ParseResult, error) {
	result := &whois.ParseResult{
		Domain:     &whois.ParsedDomain{},
		Confidence: whois.ConfidenceHigh,
		ParserName: p.Name(),
	}

	pd := result.Domain
	pd.RawResponse = response

	// Check for "No entries found" or similar
	responseLower := strings.ToLower(response)
	if strings.Contains(responseLower, "no entries found") ||
		strings.Contains(responseLower, "no object found") ||
		strings.Contains(responseLower, "object not found") {
		result.Confidence = whois.ConfidenceLow
		result.Errors = append(result.Errors, "domain not found")
		pd.DomainName = strings.ToLower(domain)
		return result, nil
	}

	// Parse the response line by line
	lines := strings.SplitSeq(response, "\n")

	for line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "%") {
			continue
		}

		// Parse key-value pairs (TCINET uses spaces around colon)
		before, after, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}

		key := strings.TrimSpace(before)
		value := strings.TrimSpace(after)

		if value == "" {
			continue
		}

		p.parseField(pd, key, value)
	}

	// Ensure domain name is set
	if pd.DomainName == "" {
		pd.DomainName = strings.ToLower(domain)
	}

	return result, nil
}

// parseField parses a single key-value field from the WHOIS response.
func (p *RUParser) parseField(pd *whois.ParsedDomain, key, value string) {
	keyLower := strings.ToLower(key)

	switch keyLower {
	case "domain":
		pd.DomainName = strings.ToLower(value)

	case "nserver":
		ns := normalizeRUNameserver(value)
		if ns != "" {
			pd.Nameservers = append(pd.Nameservers, ns)
		}

	case "state":
		// TCINET uses comma-separated states
		states := strings.Split(value, ",")
		for _, state := range states {
			state = strings.TrimSpace(state)
			if state != "" {
				pd.Status = append(pd.Status, state)
			}
		}

	case "org", "organization":
		if pd.Registrant == nil {
			pd.Registrant = &whois.ParsedEntity{}
		}
		pd.Registrant.Organization = value

	case "registrar":
		if pd.Registrar == nil {
			pd.Registrar = &whois.ParsedEntity{}
		}
		pd.Registrar.Name = value

	case "created":
		if t := parseRUDate(value); t != nil {
			pd.CreatedDate = t
		}

	case "paid-till", "expiration-date":
		if t := parseRUDate(value); t != nil {
			pd.ExpirationDate = t
		}

	case "last-updated":
		if t := parseRUDate(value); t != nil {
			pd.UpdatedDate = t
		}

	case "person":
		if pd.Registrant == nil {
			pd.Registrant = &whois.ParsedEntity{}
		}
		pd.Registrant.Name = value

	case "e-mail":
		if pd.Registrant == nil {
			pd.Registrant = &whois.ParsedEntity{}
		}
		pd.Registrant.Email = value

	case "phone":
		if pd.Registrant == nil {
			pd.Registrant = &whois.ParsedEntity{}
		}
		pd.Registrant.Phone = value
	}
}

// parseRUDate parses dates in TCINET format.
func parseRUDate(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
		"2006-01-02",
		"2006.01.02",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			t = t.UTC()
			return &t
		}
	}

	return nil
}

// normalizeRUNameserver normalizes a nameserver name from TCINET response.
func normalizeRUNameserver(ns string) string {
	ns = strings.TrimSpace(ns)
	ns = strings.ToLower(ns)
	ns = strings.TrimSuffix(ns, ".")

	// TCINET may include IP addresses after nameserver name
	if idx := strings.Index(ns, " "); idx > 0 {
		ns = ns[:idx]
	}

	return ns
}
