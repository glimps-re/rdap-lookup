package parsers

import (
	"strings"
	"time"

	"github.com/glimps-re/rdap-lookup/internal/whois"
)

// AUParser parses WHOIS responses from auDA (.au registry).
// auDA uses a specific format with sections for different contact types.
//
// Example format:
//
//	Domain Name: example.com.au
//	Registry Domain ID: D12345678-AU
//	Registrar: Example Registrar Pty Ltd
//	Status: ok
//	Registrant Contact ID: ABC123
//	Registrant Contact Name: Example Company
//	Tech Contact ID: XYZ789
//	Tech Contact Name: Technical Contact
//	Name Server: ns1.example.com.au
//	Name Server: ns2.example.com.au
//	DNSSEC: unsigned
//	Last Modified: 2024-01-15T10:30:00Z
type AUParser struct{}

// NewAUParser creates a new .au WHOIS parser.
func NewAUParser() *AUParser {
	return &AUParser{}
}

// Name returns the parser name.
func (p *AUParser) Name() string {
	return "au"
}

// SupportsTLD returns true if this parser supports the given TLD.
func (p *AUParser) SupportsTLD(tld string) bool {
	tld = strings.ToLower(tld)
	return tld == "au" || strings.HasSuffix(tld, ".au")
}

// Parse parses an auDA WHOIS response.
func (p *AUParser) Parse(response string, domain string) (*whois.ParseResult, error) {
	result := &whois.ParseResult{
		Domain:     &whois.ParsedDomain{},
		Confidence: whois.ConfidenceHigh,
		ParserName: p.Name(),
	}

	pd := result.Domain
	pd.RawResponse = response

	// Check for "No Data Found" or similar
	responseLower := strings.ToLower(response)
	if strings.Contains(responseLower, "no data found") ||
		strings.Contains(responseLower, "not found") ||
		strings.Contains(responseLower, "no entries found") ||
		strings.Contains(responseLower, "no match") {
		result.Confidence = whois.ConfidenceLow
		result.Errors = append(result.Errors, "domain not found")
		pd.DomainName = strings.ToLower(domain)
		return result, nil
	}

	// Parse the response line by line
	for line := range strings.SplitSeq(response, "\n") {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse key-value pairs
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

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
func (p *AUParser) parseField(pd *whois.ParsedDomain, key, value string) {
	keyLower := strings.ToLower(key)

	switch keyLower {
	case "domain name":
		pd.DomainName = strings.ToLower(value)

	case "registry domain id":
		pd.RegistryDomainID = value

	case "status", "domain status":
		// May contain multiple statuses on same line separated by spaces
		statuses := strings.Fields(value)
		for _, status := range statuses {
			// Remove URLs that sometimes follow status codes
			if !strings.HasPrefix(status, "http") {
				pd.Status = append(pd.Status, status)
			}
		}

	case "name server":
		ns := normalizeAUNameserver(value)
		if ns != "" {
			pd.Nameservers = append(pd.Nameservers, ns)
		}

	case "registrar", "sponsoring registrar":
		if pd.Registrar == nil {
			pd.Registrar = &whois.ParsedEntity{}
		}
		pd.Registrar.Name = value

	case "registrar abuse contact email":
		if pd.Registrar == nil {
			pd.Registrar = &whois.ParsedEntity{}
		}
		pd.Registrar.Email = value

	case "registrar abuse contact phone":
		if pd.Registrar == nil {
			pd.Registrar = &whois.ParsedEntity{}
		}
		pd.Registrar.Phone = value

	case "registrant contact id", "registrant id":
		if pd.Registrant == nil {
			pd.Registrant = &whois.ParsedEntity{}
		}
		pd.Registrant.Handle = value

	case "registrant contact name", "registrant name", "registrant":
		if pd.Registrant == nil {
			pd.Registrant = &whois.ParsedEntity{}
		}
		pd.Registrant.Name = value

	case "registrant contact email", "registrant email":
		if pd.Registrant == nil {
			pd.Registrant = &whois.ParsedEntity{}
		}
		pd.Registrant.Email = value

	case "tech contact id":
		if pd.TechContact == nil {
			pd.TechContact = &whois.ParsedEntity{}
		}
		pd.TechContact.Handle = value

	case "tech contact name":
		if pd.TechContact == nil {
			pd.TechContact = &whois.ParsedEntity{}
		}
		pd.TechContact.Name = value

	case "tech contact email":
		if pd.TechContact == nil {
			pd.TechContact = &whois.ParsedEntity{}
		}
		pd.TechContact.Email = value

	case "admin contact id":
		if pd.AdminContact == nil {
			pd.AdminContact = &whois.ParsedEntity{}
		}
		pd.AdminContact.Handle = value

	case "admin contact name":
		if pd.AdminContact == nil {
			pd.AdminContact = &whois.ParsedEntity{}
		}
		pd.AdminContact.Name = value

	case "creation date", "created", "registration date":
		if t := parseAUDate(value); t != nil {
			pd.CreatedDate = t
		}

	case "last modified", "updated date", "updated":
		if t := parseAUDate(value); t != nil {
			pd.UpdatedDate = t
		}

	case "registry expiry date", "expiration date", "expires":
		if t := parseAUDate(value); t != nil {
			pd.ExpirationDate = t
		}

	case "dnssec":
		signed := strings.ToLower(value) != "unsigned" &&
			strings.ToLower(value) != "no" &&
			strings.ToLower(value) != "n"
		pd.DNSSECSigned = &signed
	}
}

// parseAUDate parses dates in auDA format.
func parseAUDate(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	// Remove timezone abbreviations in parentheses like "(AEST)"
	if idx := strings.Index(s, "("); idx > 0 {
		s = strings.TrimSpace(s[:idx])
	}

	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05-07:00",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"02-Jan-2006",
		"02 Jan 2006",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			t = t.UTC()
			return &t
		}
	}

	return nil
}

// normalizeAUNameserver normalizes a nameserver name from auDA response.
func normalizeAUNameserver(ns string) string {
	ns = strings.TrimSpace(ns)
	ns = strings.ToLower(ns)
	ns = strings.TrimSuffix(ns, ".")

	// Remove any IP addresses that may follow
	if idx := strings.Index(ns, " "); idx > 0 {
		ns = ns[:idx]
	}

	return ns
}
