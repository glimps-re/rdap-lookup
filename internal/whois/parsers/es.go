package parsers

import (
	"strings"
	"time"

	"github.com/glimps-re/rdap-lookup/internal/whois"
)

// ESParser parses WHOIS responses from NIC.es (Red.es, .es registry).
// Red.es uses a specific format with mostly redacted information.
//
// Example format:
//
//	Nombre de dominio / Domain name: example.es
//
//	INFORMACIÓN DEL TITULAR / HOLDER INFORMATION
//	Tipo de identificación / Identification Type: NIF/NIE
//	Identificación / Identification: ***
//	Nombre / Name: ***
//	INFORMACIÓN DEL AGENTE REGISTRADOR / REGISTRAR INFORMATION
//	Nombre / Name: Example Registrar, S.L.
//	URL: https://www.example-registrar.es
//	INFORMACIÓN TÉCNICA DEL DOMINIO / TECHNICAL INFORMATION
//	Servidores DNS / DNS Servers:
//	   ns1.example.es
//	   ns2.example.es
//	Estado del dominio / Domain Status: activo/active
//	Fecha de creación / Creation Date: 01/01/2000
//	Fecha de caducidad / Expiration Date: 01/01/2025
type ESParser struct{}

// NewESParser creates a new .es WHOIS parser.
func NewESParser() *ESParser {
	return &ESParser{}
}

// Name returns the parser name.
func (p *ESParser) Name() string {
	return "es"
}

// SupportsTLD returns true if this parser supports the given TLD.
func (p *ESParser) SupportsTLD(tld string) bool {
	tld = strings.ToLower(tld)
	return tld == "es" || strings.HasSuffix(tld, ".es")
}

// Parse parses a Red.es WHOIS response.
func (p *ESParser) Parse(response string, domain string) (*whois.ParseResult, error) {
	result := &whois.ParseResult{
		Domain:     &whois.ParsedDomain{},
		Confidence: whois.ConfidenceHigh,
		ParserName: p.Name(),
	}

	pd := result.Domain
	pd.RawResponse = response

	// Check for "domain not found" or similar
	responseLower := strings.ToLower(response)
	if strings.Contains(responseLower, "no existe") ||
		strings.Contains(responseLower, "does not exist") ||
		strings.Contains(responseLower, "not found") ||
		strings.Contains(responseLower, "no match") {
		result.Confidence = whois.ConfidenceLow
		result.Errors = append(result.Errors, "domain not found")
		pd.DomainName = strings.ToLower(domain)
		return result, nil
	}

	// Parse the response line by line
	lines := strings.Split(response, "\n")
	currentSection := ""
	inDNSSection := false

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		// Skip empty lines
		if trimmedLine == "" {
			continue
		}

		// Check for section headers (bilingual format)
		lineLower := strings.ToLower(trimmedLine)
		if strings.Contains(lineLower, "información del titular") || strings.Contains(lineLower, "holder information") {
			currentSection = "holder"
			continue
		}
		if strings.Contains(lineLower, "información del agente") || strings.Contains(lineLower, "registrar information") {
			currentSection = "registrar"
			continue
		}
		if strings.Contains(lineLower, "información técnica") || strings.Contains(lineLower, "technical information") {
			currentSection = "technical"
			continue
		}

		// Check for DNS servers section
		if strings.Contains(lineLower, "servidores dns") || strings.Contains(lineLower, "dns servers") {
			inDNSSection = true
			continue
		}

		// If in DNS section and line is indented, it's a nameserver
		if inDNSSection {
			if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
				ns := normalizeESNameserver(trimmedLine)
				if ns != "" {
					pd.Nameservers = append(pd.Nameservers, ns)
				}
				continue
			}
			// Not indented anymore, exit DNS section
			inDNSSection = false
		}

		// Parse key-value pairs (bilingual format: "Spanish / English: value")
		before, after, ok := strings.Cut(trimmedLine, ":")
		if !ok {
			continue
		}

		key := strings.TrimSpace(before)
		value := strings.TrimSpace(after)

		// Skip redacted values
		if value == "" || value == "***" || strings.HasPrefix(value, "***") {
			continue
		}

		// Extract the English key from bilingual format
		if slashIdx := strings.Index(key, "/"); slashIdx > 0 {
			key = strings.TrimSpace(key[slashIdx+1:])
		}

		p.parseField(pd, currentSection, key, value)
	}

	// Ensure domain name is set
	if pd.DomainName == "" {
		pd.DomainName = strings.ToLower(domain)
	}

	return result, nil
}

// parseField parses a field based on section.
func (p *ESParser) parseField(pd *whois.ParsedDomain, section, key, value string) {
	keyLower := strings.ToLower(key)

	switch section {
	case "":
		// Top-level fields
		switch {
		case strings.Contains(keyLower, "domain name") || strings.Contains(keyLower, "nombre de dominio"):
			pd.DomainName = strings.ToLower(value)
		case strings.Contains(keyLower, "domain status") || strings.Contains(keyLower, "estado"):
			pd.Status = append(pd.Status, value)
		case strings.Contains(keyLower, "creation date") || strings.Contains(keyLower, "fecha de creación"):
			if t := parseESDate(value); t != nil {
				pd.CreatedDate = t
			}
		case strings.Contains(keyLower, "expiration date") || strings.Contains(keyLower, "fecha de caducidad"):
			if t := parseESDate(value); t != nil {
				pd.ExpirationDate = t
			}
		}
	case "holder":
		if pd.Registrant == nil {
			pd.Registrant = &whois.ParsedEntity{}
		}
		switch {
		case strings.Contains(keyLower, "name"):
			pd.Registrant.Name = value
		case strings.Contains(keyLower, "organization"):
			pd.Registrant.Organization = value
		}
	case "registrar":
		if pd.Registrar == nil {
			pd.Registrar = &whois.ParsedEntity{}
		}
		switch {
		case strings.Contains(keyLower, "name"):
			pd.Registrar.Name = value
		case keyLower == "url":
			pd.Registrar.Address = value
		}
	case "technical":
		// Technical info section also contains status and dates
		switch {
		case strings.Contains(keyLower, "domain status") || strings.Contains(keyLower, "estado"):
			pd.Status = append(pd.Status, value)
		case strings.Contains(keyLower, "creation date") || strings.Contains(keyLower, "fecha de creación"):
			if t := parseESDate(value); t != nil {
				pd.CreatedDate = t
			}
		case strings.Contains(keyLower, "expiration date") || strings.Contains(keyLower, "fecha de caducidad"):
			if t := parseESDate(value); t != nil {
				pd.ExpirationDate = t
			}
		}
	}
}

// parseESDate parses dates in Red.es format (DD/MM/YYYY).
func parseESDate(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	formats := []string{
		"02/01/2006", // DD/MM/YYYY
		"2/1/2006",   // D/M/YYYY
		"2006-01-02", // YYYY-MM-DD
		"02-01-2006", // DD-MM-YYYY
		time.RFC3339,
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			t = t.UTC()
			return &t
		}
	}

	return nil
}

// normalizeESNameserver normalizes a nameserver name.
func normalizeESNameserver(ns string) string {
	ns = strings.TrimSpace(ns)
	ns = strings.ToLower(ns)
	ns = strings.TrimSuffix(ns, ".")

	// Must contain at least one dot
	if !strings.Contains(ns, ".") {
		return ""
	}

	return ns
}
