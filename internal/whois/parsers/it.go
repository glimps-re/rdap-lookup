package parsers

import (
	"strings"
	"time"

	"github.com/glimps-re/rdap-lookup/internal/whois"
)

// ITParser parses WHOIS responses from NIC.it (.it registry).
// NIC.it uses a specific format with sections for different contact types.
//
// Example format:
//
//	Domain:             example.it
//	Status:             ok
//
//	Created:            2000-01-15 00:00:00
//	Last Update:        2024-01-15 10:30:00
//	Expire Date:        2025-01-15
//
//	Registrant
//	  Organization:     Example S.r.l.
//	  Address:          Via Example 123
//	                    00100 Roma (RM)
//	                    IT
//	  Created:          2000-01-15 00:00:00
//	  Last Update:      2024-01-15 10:30:00
//
//	Admin Contact
//	  Name:             Admin Contact Name
//	  Organization:     Example S.r.l.
//
//	Technical Contacts
//	  Name:             Technical Contact Name
//	  Organization:     Example Hosting
//
//	Registrar
//	  Organization:     Example Registrar S.r.l.
//	  Name:             EXAMPLE-REG
//	  Web:              https://www.example-registrar.it
//
//	Nameservers
//	  ns1.example.it
//	  ns2.example.it
type ITParser struct{}

// NewITParser creates a new .it WHOIS parser.
func NewITParser() *ITParser {
	return &ITParser{}
}

// Name returns the parser name.
func (p *ITParser) Name() string {
	return "it"
}

// SupportsTLD returns true if this parser supports the given TLD.
func (p *ITParser) SupportsTLD(tld string) bool {
	return strings.ToLower(tld) == "it"
}

// Parse parses a NIC.it WHOIS response.
func (p *ITParser) Parse(response string, domain string) (*whois.ParseResult, error) {
	result := &whois.ParseResult{
		Domain:     &whois.ParsedDomain{},
		Confidence: whois.ConfidenceHigh,
		ParserName: p.Name(),
	}

	pd := result.Domain
	pd.RawResponse = response

	// Check for "Status: AVAILABLE" or "AVAILABLE"
	responseLower := strings.ToLower(response)
	if strings.Contains(responseLower, "status:             available") ||
		strings.Contains(responseLower, "object not found") ||
		strings.Contains(responseLower, "no entries found") {
		result.Confidence = whois.ConfidenceLow
		result.Errors = append(result.Errors, "domain not found or available")
		pd.DomainName = strings.ToLower(domain)
		return result, nil
	}

	// Parse the response line by line
	currentSection := ""

	for i := range lines {
		line := lines[i]
		trimmedLine := strings.TrimSpace(line)

		// Skip empty lines and comments
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "*") {
			continue
		}

		// Check for section headers (lines without colons that match known sections)
		sectionLower := strings.ToLower(trimmedLine)
		switch sectionLower {
		case "registrant":
			currentSection = "registrant"
			continue
		case "admin contact", "admin":
			currentSection = "admin"
			continue
		case "technical contacts", "technical contact", "tech contact", "tech":
			currentSection = "tech"
			continue
		case "registrar":
			currentSection = "registrar"
			continue
		case "nameservers":
			currentSection = "nameservers"
			continue
		}

		// Check if line is indented (part of current section)
		isIndented := len(line) > 0 && (line[0] == ' ' || line[0] == '\t')

		// If not indented and contains colon, it's a top-level field
		if !isIndented && strings.Contains(trimmedLine, ":") {
			currentSection = ""
		}

		// Parse based on section
		before, after, ok := strings.Cut(trimmedLine, ":")
		if !ok {
			// No colon - could be nameserver or continuation
			if currentSection == "nameservers" {
				ns := normalizeITNameserver(trimmedLine)
				if ns != "" {
					pd.Nameservers = append(pd.Nameservers, ns)
				}
			}
			continue
		}

		key := strings.TrimSpace(before)
		value := strings.TrimSpace(after)

		if value == "" {
			continue
		}

		// Handle fields based on section
		switch currentSection {
		case "":
			p.parseTopLevel(pd, key, value)
		case "registrant":
			if pd.Registrant == nil {
				pd.Registrant = &whois.ParsedEntity{}
			}
			p.parseContact(pd.Registrant, key, value)
		case "admin":
			if pd.AdminContact == nil {
				pd.AdminContact = &whois.ParsedEntity{}
			}
			p.parseContact(pd.AdminContact, key, value)
		case "tech":
			if pd.TechContact == nil {
				pd.TechContact = &whois.ParsedEntity{}
			}
			p.parseContact(pd.TechContact, key, value)
		case "registrar":
			if pd.Registrar == nil {
				pd.Registrar = &whois.ParsedEntity{}
			}
			p.parseRegistrar(pd.Registrar, key, value)
		}
	}

	// Ensure domain name is set
	if pd.DomainName == "" {
		pd.DomainName = strings.ToLower(domain)
	}

	return result, nil
}

// parseTopLevel parses top-level domain fields.
func (p *ITParser) parseTopLevel(pd *whois.ParsedDomain, key, value string) {
	switch strings.ToLower(key) {
	case "domain":
		pd.DomainName = strings.ToLower(value)
	case "status":
		pd.Status = append(pd.Status, value)
	case "created":
		if t := parseITDate(value); t != nil {
			pd.CreatedDate = t
		}
	case "last update":
		if t := parseITDate(value); t != nil {
			pd.UpdatedDate = t
		}
	case "expire date":
		if t := parseITDate(value); t != nil {
			pd.ExpirationDate = t
		}
	case "dnssec":
		signed := strings.ToLower(value) != "no" && strings.ToLower(value) != "unsigned"
		pd.DNSSECSigned = &signed
	}
}

// parseContact parses contact fields.
func (p *ITParser) parseContact(entity *whois.ParsedEntity, key, value string) {
	switch strings.ToLower(key) {
	case "name":
		entity.Name = value
	case "organization", "organisation":
		entity.Organization = value
	case "address":
		if entity.Address == "" {
			entity.Address = value
		} else {
			entity.Address += ", " + value
		}
	case "entityid":
		entity.Handle = value
	}
}

// parseRegistrar parses registrar fields.
func (p *ITParser) parseRegistrar(entity *whois.ParsedEntity, key, value string) {
	switch strings.ToLower(key) {
	case "organization", "organisation":
		entity.Organization = value
	case "name":
		entity.Name = value
	case "web":
		entity.Address = value
	}
}

// parseITDate parses dates in NIC.it format.
func parseITDate(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	formats := []string{
		"2006-01-02 15:04:05",
		"2006-01-02",
		time.RFC3339,
		"2006-01-02T15:04:05Z",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			t = t.UTC()
			return &t
		}
	}

	return nil
}

// normalizeITNameserver normalizes a nameserver name.
func normalizeITNameserver(ns string) string {
	ns = strings.TrimSpace(ns)
	ns = strings.ToLower(ns)
	ns = strings.TrimSuffix(ns, ".")

	// Must contain at least one dot
	if !strings.Contains(ns, ".") {
		return ""
	}

	return ns
}
