package whois

import (
	"regexp"
	"strings"
	"time"
)

// GenericParser is a best-effort WHOIS parser for unknown TLDs.
// It extracts common fields using heuristics and pattern matching.
type GenericParser struct {
	// Field extractors
	domainNameExtractor      *fieldExtractor
	statusExtractor          *fieldExtractor
	nameserverExtractor      *fieldExtractor
	createdDateExtractor     *fieldExtractor
	updatedDateExtractor     *fieldExtractor
	expirationDateExtractor  *fieldExtractor
	registrarExtractor       *fieldExtractor
	registrantExtractor      *fieldExtractor
	registrantOrgExtractor   *fieldExtractor
	registrantEmailExtractor *fieldExtractor
	adminEmailExtractor      *fieldExtractor
	techEmailExtractor       *fieldExtractor
	dnssecExtractor          *fieldExtractor
}

// NewGenericParser creates a new generic WHOIS parser.
func NewGenericParser() *GenericParser {
	return &GenericParser{
		domainNameExtractor: newFieldExtractor(
			"Domain Name",
			"Domain",
			"domain name",
		),
		statusExtractor: newFieldExtractor(
			"Domain Status",
			"Status",
			"state",
		),
		nameserverExtractor: newFieldExtractor(
			"Name Server",
			"Nameserver",
			"nserver",
			"NS",
			"Nserver",
		),
		createdDateExtractor: newFieldExtractor(
			"Creation Date",
			"Created Date",
			"Created",
			"created on",
			"Registration Date",
			"Registration Time",
			"Registered Date",
			"Registered on",
			"Domain Registration Date",
		),
		updatedDateExtractor: newFieldExtractor(
			"Updated Date",
			"Last Updated",
			"Last Modified",
			"Modified",
			"Changed",
			"changed",
			"Last Update",
		),
		expirationDateExtractor: newFieldExtractor(
			"Registry Expiry Date",
			"Expiration Date",
			"Expiry Date",
			"Expiration Time",
			"Expires",
			"Expires on",
			"paid-till",
		),
		registrarExtractor: newFieldExtractor(
			"Registrar",
			"Sponsoring Registrar",
			"Registrar Name",
		),
		registrantExtractor: newFieldExtractor(
			"Registrant Name",
			"Registrant",
			"Holder",
			"Owner",
		),
		registrantOrgExtractor: newFieldExtractor(
			"Registrant Organization",
			"Registrant Organisation",
			"Registrant Org",
			"Organization",
			"Organisation",
		),
		registrantEmailExtractor: newFieldExtractor(
			"Registrant Email",
			"Registrant Contact Email",
		),
		adminEmailExtractor: newFieldExtractor(
			"Admin Email",
			"Administrative Contact Email",
		),
		techEmailExtractor: newFieldExtractor(
			"Tech Email",
			"Technical Contact Email",
		),
		dnssecExtractor: newFieldExtractor(
			"DNSSEC",
			"dnssec",
		),
	}
}

// Name returns the parser name.
func (p *GenericParser) Name() string {
	return "generic"
}

// SupportsTLD returns true - generic parser supports all TLDs as fallback.
func (p *GenericParser) SupportsTLD(_ string) bool {
	return true
}

// Parse parses a WHOIS response and returns the extracted domain data.
func (p *GenericParser) Parse(response string, domain string) (*ParseResult, error) {
	result := &ParseResult{
		Domain:     &ParsedDomain{},
		Confidence: ConfidenceLow,
		ParserName: p.Name(),
	}

	pd := result.Domain

	// Extract domain name
	pd.DomainName = p.domainNameExtractor.Extract(response)
	if pd.DomainName == "" {
		// Use the provided domain as fallback
		pd.DomainName = strings.ToLower(domain)
	}
	pd.DomainName = strings.ToLower(pd.DomainName)

	// Extract status
	pd.Status = p.statusExtractor.ExtractAll(response)

	// Extract nameservers
	ns := p.nameserverExtractor.ExtractAll(response)
	for _, n := range ns {
		// Normalize nameserver names
		n = normalizeNameserver(n)
		if n != "" {
			pd.Nameservers = append(pd.Nameservers, n)
		}
	}

	// Extract dates
	if created := p.createdDateExtractor.Extract(response); created != "" {
		if t := parseDate(created); t != nil {
			pd.CreatedDate = t
		}
	}
	if updated := p.updatedDateExtractor.Extract(response); updated != "" {
		if t := parseDate(updated); t != nil {
			pd.UpdatedDate = t
		}
	}
	if expiry := p.expirationDateExtractor.Extract(response); expiry != "" {
		if t := parseDate(expiry); t != nil {
			pd.ExpirationDate = t
		}
	}

	// Extract registrar
	if registrar := p.registrarExtractor.Extract(response); registrar != "" {
		pd.Registrar = &ParsedEntity{
			Name: registrar,
		}
	}

	// Extract registrant
	registrantName := p.registrantExtractor.Extract(response)
	registrantOrg := p.registrantOrgExtractor.Extract(response)
	registrantEmail := p.registrantEmailExtractor.Extract(response)
	if registrantName != "" || registrantOrg != "" || registrantEmail != "" {
		pd.Registrant = &ParsedEntity{
			Name:         registrantName,
			Organization: registrantOrg,
			Email:        registrantEmail,
		}
	}

	// Extract DNSSEC
	dnssec := p.dnssecExtractor.Extract(response)
	if dnssec != "" {
		signed := isDNSSECSigned(dnssec)
		pd.DNSSECSigned = &signed
	}

	// Store raw response
	pd.RawResponse = response

	return result, nil
}

// parseDate attempts to parse a date string in various formats.
// Returns nil if parsing fails.
func parseDate(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	// Common date formats in WHOIS responses
	formats := []string{
		// ISO 8601 / RFC 3339
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05-07:00",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02 15:04:05Z",
		"2006-01-02 15:04:05-07:00",
		"2006-01-02",
		// US formats
		"01/02/2006",
		"01-02-2006",
		"02-Jan-2006",
		"02 Jan 2006",
		// European formats
		"02/01/2006",
		"02.01.2006",
		// Other common formats
		"20060102",
		"2006/01/02",
		"January 2, 2006",
		"Jan 2, 2006",
		"2 January 2006",
		"2 Jan 2006",
		// With time
		"2006-01-02 15:04:05 (UTC)",
		"2006-01-02 15:04:05 UTC",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			t = t.UTC()
			return &t
		}
	}

	// Try to extract date from strings like "2024-01-15T10:30:00+01:00 (CET)"
	// by trimming timezone info after the offset
	if idx := strings.Index(s, " ("); idx > 0 {
		trimmed := strings.TrimSpace(s[:idx])
		return parseDate(trimmed)
	}

	return nil
}

// normalizeNameserver normalizes a nameserver hostname.
func normalizeNameserver(ns string) string {
	ns = strings.TrimSpace(ns)
	ns = strings.ToLower(ns)

	// Remove IP addresses that sometimes appear after nameserver names
	// e.g., "ns1.example.com 192.168.1.1"
	if idx := strings.Index(ns, " "); idx > 0 {
		ns = ns[:idx]
	}

	// Remove trailing dots
	ns = strings.TrimSuffix(ns, ".")

	return ns
}

// isDNSSECSigned checks if the DNSSEC value indicates the domain is signed.
func isDNSSECSigned(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))

	// Positive indicators
	if value == "signed" || value == "yes" || value == "signeddelegation" {
		return true
	}

	// Negative indicators
	if value == "unsigned" || value == "no" || value == "inactive" {
		return false
	}

	// Check for presence of DS record info (indicates signed)
	if strings.Contains(value, "ds") || strings.Contains(value, "dnskey") {
		return true
	}

	return false
}

// extractCountry attempts to extract a country code from WHOIS response.
// This is a best-effort extraction using common patterns.
func extractCountry(response string) string {
	// Common country field patterns
	patterns := []string{
		"Registrant Country",
		"Country",
		"country",
		"Registrant State/Province",
	}

	extractor := newFieldExtractor(patterns...)
	value := extractor.Extract(response)

	// Validate it looks like a country code (2-letter)
	if len(value) == 2 {
		return strings.ToUpper(value)
	}

	// Try to extract from longer country names using regex
	// Pattern for 2-letter country code at end of address
	re := regexp.MustCompile(`\b([A-Z]{2})\b\s*$`)
	if matches := re.FindStringSubmatch(value); len(matches) > 1 {
		return matches[1]
	}

	return ""
}
