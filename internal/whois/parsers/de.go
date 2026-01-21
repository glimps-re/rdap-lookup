package parsers

import (
	"strings"
	"time"

	"github.com/glimps-re/rdap-lookup/internal/whois"
)

// DEParser parses WHOIS responses from DENIC (.de registry).
// DENIC uses a unique format with sections for contacts.
//
// Example format:
//
//	Domain: example.de
//	Nserver: ns1.example.de
//	Nserver: ns2.example.de
//	Status: connect
//	Changed: 2024-01-15T10:30:00+01:00
//
//	[Tech-C]
//	Type: PERSON
//	Name: Technical Contact
//	...
type DEParser struct{}

// NewDEParser creates a new .de WHOIS parser.
func NewDEParser() *DEParser {
	return &DEParser{}
}

// Name returns the parser name.
func (p *DEParser) Name() string {
	return "de"
}

// SupportsTLD returns true if this parser supports the given TLD.
func (p *DEParser) SupportsTLD(tld string) bool {
	return strings.ToLower(tld) == "de"
}

// Parse parses a DENIC WHOIS response.
func (p *DEParser) Parse(response string, domain string) (*whois.ParseResult, error) {
	result := &whois.ParseResult{
		Domain:     &whois.ParsedDomain{},
		Confidence: whois.ConfidenceHigh,
		ParserName: p.Name(),
	}

	pd := result.Domain
	pd.RawResponse = response

	// Check for "Status: free" or "% Object not found"
	responseLower := strings.ToLower(response)
	if strings.Contains(response, "Status: free") ||
		strings.Contains(responseLower, "object not found") ||
		strings.Contains(responseLower, "no entries found") {
		result.Confidence = whois.ConfidenceLow
		result.Errors = append(result.Errors, "domain not found or free")
		pd.DomainName = strings.ToLower(domain)
		return result, nil
	}

	// Parse the response line by line
	lines := strings.Split(response, "\n")
	currentSection := ""

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "%") {
			continue
		}

		// Check for section headers like [Tech-C], [Zone-C], [Holder]
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}

		// Parse key-value pairs
		colonIdx := strings.Index(line, ":")
		if colonIdx == -1 {
			continue
		}

		key := strings.TrimSpace(line[:colonIdx])
		value := strings.TrimSpace(line[colonIdx+1:])

		if value == "" {
			continue
		}

		// Handle fields based on current section
		switch currentSection {
		case "":
			// Main domain section
			p.parseMainSection(pd, key, value)
		case "holder":
			// Registrant information
			if pd.Registrant == nil {
				pd.Registrant = &whois.ParsedEntity{}
			}
			p.parseContact(pd.Registrant, key, value)
		case "admin-c":
			// Admin contact
			if pd.AdminContact == nil {
				pd.AdminContact = &whois.ParsedEntity{}
			}
			p.parseContact(pd.AdminContact, key, value)
		case "tech-c":
			// Technical contact
			if pd.TechContact == nil {
				pd.TechContact = &whois.ParsedEntity{}
			}
			p.parseContact(pd.TechContact, key, value)
		case "zone-c":
			// Zone contact (map to tech)
			if pd.TechContact == nil {
				pd.TechContact = &whois.ParsedEntity{}
			}
			p.parseContact(pd.TechContact, key, value)
		}
	}

	// Ensure domain name is set
	if pd.DomainName == "" {
		pd.DomainName = strings.ToLower(domain)
	}

	return result, nil
}

// parseMainSection parses fields in the main domain section.
func (p *DEParser) parseMainSection(pd *whois.ParsedDomain, key, value string) {
	switch strings.ToLower(key) {
	case "domain":
		pd.DomainName = strings.ToLower(value)
	case "nserver":
		ns := normalizeNameserver(value)
		if ns != "" {
			pd.Nameservers = append(pd.Nameservers, ns)
		}
	case "status":
		pd.Status = append(pd.Status, value)
	case "changed":
		if t := parseDEDate(value); t != nil {
			pd.UpdatedDate = t
		}
	case "regcreateddate":
		if t := parseDEDate(value); t != nil {
			pd.CreatedDate = t
		}
	case "dnskey":
		signed := true
		pd.DNSSECSigned = &signed
	case "dnssec":
		signed := value != "N" && value != "unsigned"
		pd.DNSSECSigned = &signed
	}
}

// parseContact parses contact fields.
func (p *DEParser) parseContact(entity *whois.ParsedEntity, key, value string) {
	switch strings.ToLower(key) {
	case "name":
		entity.Name = value
	case "organisation", "organization":
		entity.Organization = value
	case "address":
		if entity.Address == "" {
			entity.Address = value
		} else {
			entity.Address += ", " + value
		}
	case "city":
		entity.City = value
	case "postalcode":
		entity.PostalCode = value
	case "countrycode", "country":
		entity.Country = strings.ToUpper(value)
	case "email":
		entity.Email = value
	case "phone":
		entity.Phone = value
	case "fax":
		entity.Fax = value
	}
}

// parseDEDate parses dates in DENIC format (e.g., "2024-01-15T10:30:00+01:00").
func parseDEDate(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05-07:00",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			t = t.UTC()
			return &t
		}
	}

	return nil
}

// normalizeNameserver normalizes a nameserver name.
func normalizeNameserver(ns string) string {
	ns = strings.TrimSpace(ns)
	ns = strings.ToLower(ns)

	// DENIC format may include IP: "ns1.example.de 192.168.1.1"
	if idx := strings.Index(ns, " "); idx > 0 {
		ns = ns[:idx]
	}

	ns = strings.TrimSuffix(ns, ".")
	return ns
}
