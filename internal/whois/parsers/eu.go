package parsers

import (
	"strings"
	"time"

	"github.com/glimps-re/rdap-lookup/internal/whois"
)

// EUParser parses WHOIS responses from EURid (.eu registry).
// EURid uses a specific format with sections for registrant and technical info.
//
// Example format:
//
//	Domain: example.eu
//	Script: LATIN
//	Registrant:
//	        NOT DISCLOSED!
//	        Visit www.eurid.eu for webbased whois.
//	Technical:
//	        Name: Technical Contact
//	        Organisation: Example Tech Ltd
//	        Language: en
//	        Phone: +32.123456789
//	        Fax: +32.123456780
//	        Email: tech@example.eu
//	Registrar:
//	        Name: Example Registrar
//	        Website: https://www.example-registrar.eu
//	Name servers:
//	        ns1.example.eu
//	        ns2.example.eu
//	Keys:
//	        keyTag:12345 flags:257 protocol:3 algorithm:13
//	DNSSEC:
//	        signedDelegation
//	Please visit www.eurid.eu for more info.
type EUParser struct{}

// NewEUParser creates a new .eu WHOIS parser.
func NewEUParser() *EUParser {
	return &EUParser{}
}

// Name returns the parser name.
func (p *EUParser) Name() string {
	return "eu"
}

// SupportsTLD returns true if this parser supports the given TLD.
func (p *EUParser) SupportsTLD(tld string) bool {
	return strings.ToLower(tld) == "eu"
}

// Parse parses a EURid WHOIS response.
func (p *EUParser) Parse(response string, domain string) (*whois.ParseResult, error) {
	result := &whois.ParseResult{
		Domain:     &whois.ParsedDomain{},
		Confidence: whois.ConfidenceHigh,
		ParserName: p.Name(),
	}

	pd := result.Domain
	pd.RawResponse = response

	// Check for "Status: AVAILABLE" or "NOT FOUND"
	responseLower := strings.ToLower(response)
	if strings.Contains(responseLower, "status: available") ||
		strings.Contains(responseLower, "not found") ||
		strings.Contains(responseLower, "no entries found") {
		result.Confidence = whois.ConfidenceLow
		result.Errors = append(result.Errors, "domain not found or available")
		pd.DomainName = strings.ToLower(domain)
		return result, nil
	}

	// Parse the response line by line
	lines := strings.Split(response, "\n")
	currentSection := ""

	for _, line := range lines {
		// Don't trim the line yet - we need to detect indentation for sections
		trimmedLine := strings.TrimSpace(line)

		// Skip empty lines and comments
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "%") {
			continue
		}

		// Check for section headers (lines ending with colon but no value after)
		if strings.HasSuffix(trimmedLine, ":") && !strings.Contains(trimmedLine[:len(trimmedLine)-1], ":") {
			sectionName := strings.ToLower(strings.TrimSuffix(trimmedLine, ":"))
			// Known sections
			switch sectionName {
			case "registrant", "technical", "tech", "registrar", "name servers", "nameservers", "keys", "dnssec":
				currentSection = sectionName
			default:
				currentSection = ""
			}
			continue
		}

		// Check if this is an indented line (part of a section)
		isIndented := len(line) > 0 && (line[0] == '\t' || line[0] == ' ')

		// If not indented, it's a top-level field
		if !isIndented {
			// Reset section
			currentSection = ""
		}

		// Parse key-value pairs
		colonIdx := strings.Index(trimmedLine, ":")
		if colonIdx == -1 {
			// No colon - could be a nameserver or DNSSEC value
			switch currentSection {
			case "name servers", "nameservers":
				ns := normalizeEUNameserver(trimmedLine)
				if ns != "" {
					pd.Nameservers = append(pd.Nameservers, ns)
				}
			case "dnssec":
				// DNSSEC section with just a value like "signedDelegation"
				p.parseDNSSEC(pd, trimmedLine)
			}
			continue
		}

		key := strings.TrimSpace(trimmedLine[:colonIdx])
		value := strings.TrimSpace(trimmedLine[colonIdx+1:])

		if value == "" || strings.Contains(strings.ToLower(value), "not disclosed") {
			continue
		}

		// Handle fields based on current section
		switch currentSection {
		case "":
			// Top-level fields
			p.parseTopLevel(pd, key, value)
		case "registrant":
			// Registrant information (usually redacted for .eu)
			if pd.Registrant == nil {
				pd.Registrant = &whois.ParsedEntity{}
			}
			p.parseContact(pd.Registrant, key, value)
		case "technical", "tech":
			// Technical contact
			if pd.TechContact == nil {
				pd.TechContact = &whois.ParsedEntity{}
			}
			p.parseContact(pd.TechContact, key, value)
		case "registrar":
			// Registrar info
			if pd.Registrar == nil {
				pd.Registrar = &whois.ParsedEntity{}
			}
			p.parseRegistrar(pd.Registrar, key, value)
		case "dnssec":
			// DNSSEC section
			p.parseDNSSEC(pd, value)
		}
	}

	// Ensure domain name is set
	if pd.DomainName == "" {
		pd.DomainName = strings.ToLower(domain)
	}

	return result, nil
}

// parseTopLevel parses top-level fields.
func (p *EUParser) parseTopLevel(pd *whois.ParsedDomain, key, value string) {
	switch strings.ToLower(key) {
	case "domain":
		pd.DomainName = strings.ToLower(value)
	case "status":
		pd.Status = append(pd.Status, value)
	case "registered":
		if t := parseEUDate(value); t != nil {
			pd.CreatedDate = t
		}
	}
}

// parseContact parses contact fields.
func (p *EUParser) parseContact(entity *whois.ParsedEntity, key, value string) {
	switch strings.ToLower(key) {
	case "name":
		entity.Name = value
	case "organisation", "organization":
		entity.Organization = value
	case "email":
		entity.Email = value
	case "phone":
		entity.Phone = value
	case "fax":
		entity.Fax = value
	}
}

// parseRegistrar parses registrar fields.
func (p *EUParser) parseRegistrar(entity *whois.ParsedEntity, key, value string) {
	switch strings.ToLower(key) {
	case "name":
		entity.Name = value
	case "website":
		// Store website in Address field for now
		entity.Address = value
	}
}

// parseDNSSEC parses DNSSEC value.
func (p *EUParser) parseDNSSEC(pd *whois.ParsedDomain, value string) {
	valueLower := strings.ToLower(value)
	signed := valueLower == "signeddelegation" || valueLower == "yes" || valueLower == "signed"
	pd.DNSSECSigned = &signed
}

// parseEUDate parses dates in EURid format.
func parseEUDate(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
		"2006-01-02",
		"02.01.2006",
		"Mon Jan 2 15:04:05 2006",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			t = t.UTC()
			return &t
		}
	}

	return nil
}

// normalizeEUNameserver normalizes a nameserver name.
func normalizeEUNameserver(ns string) string {
	ns = strings.TrimSpace(ns)
	ns = strings.ToLower(ns)
	ns = strings.TrimSuffix(ns, ".")

	// Skip if it contains space or equals (likely a key record)
	if strings.ContainsAny(ns, " =") {
		return ""
	}

	// Must contain at least one dot to be a valid nameserver
	if !strings.Contains(ns, ".") {
		return ""
	}

	return ns
}
