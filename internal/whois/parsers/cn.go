package parsers

import (
	"strings"
	"time"

	"github.com/glimps-re/rdap-lookup/internal/whois"
)

// CNParser parses WHOIS responses from CNNIC (.cn registry).
// CNNIC uses a unique format with Chinese and English labels.
//
// Example format:
//
//	Domain Name: example.cn
//	ROID: 20030311s10001s00047706-cn
//	Domain Status: ok
//	Registrant ID: abc123
//	Registrant: Example Company
//	Registrant Contact Email: admin@example.cn
//	Sponsoring Registrar: Example Registrar
//	Name Server: ns1.example.cn
//	Name Server: ns2.example.cn
//	Registration Time: 2003-03-17 12:20:05
//	Expiration Time: 2025-03-17 12:48:36
type CNParser struct{}

// NewCNParser creates a new .cn WHOIS parser.
func NewCNParser() *CNParser {
	return &CNParser{}
}

// Name returns the parser name.
func (p *CNParser) Name() string {
	return "cn"
}

// SupportsTLD returns true if this parser supports the given TLD.
func (p *CNParser) SupportsTLD(tld string) bool {
	tld = strings.ToLower(tld)
	return tld == "cn" || strings.HasSuffix(tld, ".cn")
}

// Parse parses a CNNIC WHOIS response.
func (p *CNParser) Parse(response string, domain string) (*whois.ParseResult, error) {
	result := &whois.ParseResult{
		Domain:     &whois.ParsedDomain{},
		Confidence: whois.ConfidenceHigh,
		ParserName: p.Name(),
	}

	pd := result.Domain
	pd.RawResponse = response

	// Check for "No matching record" or similar
	responseLower := strings.ToLower(response)
	if strings.Contains(responseLower, "no matching record") ||
		strings.Contains(responseLower, "no entries found") ||
		strings.Contains(responseLower, "not found") {
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
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, ">") {
			continue
		}

		// Parse key-value pairs
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
func (p *CNParser) parseField(pd *whois.ParsedDomain, key, value string) {
	keyLower := strings.ToLower(key)

	switch keyLower {
	case "domain name":
		pd.DomainName = strings.ToLower(value)

	case "roid":
		pd.RegistryDomainID = value

	case "domain status":
		pd.Status = append(pd.Status, value)

	case "name server":
		ns := normalizeCNNameserver(value)
		if ns != "" {
			pd.Nameservers = append(pd.Nameservers, ns)
		}

	case "registration time", "registration date":
		if t := parseCNDate(value); t != nil {
			pd.CreatedDate = t
		}

	case "expiration time", "expiration date", "expiry date":
		if t := parseCNDate(value); t != nil {
			pd.ExpirationDate = t
		}

	case "sponsoring registrar", "registrar":
		if pd.Registrar == nil {
			pd.Registrar = &whois.ParsedEntity{}
		}
		pd.Registrar.Name = value

	case "registrant", "registrant name":
		if pd.Registrant == nil {
			pd.Registrant = &whois.ParsedEntity{}
		}
		pd.Registrant.Name = value

	case "registrant id":
		if pd.Registrant == nil {
			pd.Registrant = &whois.ParsedEntity{}
		}
		pd.Registrant.Handle = value

	case "registrant contact email", "registrant email":
		if pd.Registrant == nil {
			pd.Registrant = &whois.ParsedEntity{}
		}
		pd.Registrant.Email = value

	case "dnssec":
		signed := strings.ToLower(value) != "unsigned" && strings.ToLower(value) != "no"
		pd.DNSSECSigned = &signed
	}
}

// parseCNDate parses dates in CNNIC format (e.g., "2003-03-17 12:20:05").
func parseCNDate(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	formats := []string{
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
		"2006-01-02",
		"2006/01/02",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			t = t.UTC()
			return &t
		}
	}

	return nil
}

// normalizeCNNameserver normalizes a nameserver name from CNNIC response.
func normalizeCNNameserver(ns string) string {
	ns = strings.TrimSpace(ns)
	ns = strings.ToLower(ns)
	ns = strings.TrimSuffix(ns, ".")
	return ns
}
