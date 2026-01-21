package parsers

import (
	"strings"
	"time"

	"github.com/glimps-re/rdap-lookup/internal/whois"
)

// JPParser parses WHOIS responses from JPRS (.jp registry).
// JPRS uses a specific format with Japanese and English labels.
//
// Example format:
//
//	[ JPRS database provides information on network administration. Its use is    ]
//	[ restricted to network administration purposes. For further information,     ]
//	[ use 'whois -h whois.jprs.jp help'. To suppress Japanese output, add'/e'     ]
//	[ at the end of command, e.g. 'whois -h whois.jprs.jp xxx/e'.                 ]
//
//	Domain Information: [ドメイン情報]
//	a. [ドメイン名]                 EXAMPLE.JP
//	b. [ねっとわーくさーびすめい]   えぐざんぷる
//	c. [ネットワークサービス名]     EXAMPLE
//	d. [Network Service Name]       EXAMPLE
//	g. [Organization]               Example Corporation
//	l. [Organization Type]          Corporation
//	m. [登録担当者]                 XX12345JP
//	n. [技術連絡担当者]             YY67890JP
//	p. [ネームサーバ]               ns1.example.jp
//	p. [ネームサーバ]               ns2.example.jp
//	s. [署名鍵]
//	[状態]                          Active
//	[登録年月日]                    2000/01/15
//	[接続年月日]                    2000/01/15
//	[最終更新]                      2024/01/15 10:30:00 (JST)
type JPParser struct{}

// NewJPParser creates a new .jp WHOIS parser.
func NewJPParser() *JPParser {
	return &JPParser{}
}

// Name returns the parser name.
func (p *JPParser) Name() string {
	return "jp"
}

// SupportsTLD returns true if this parser supports the given TLD.
func (p *JPParser) SupportsTLD(tld string) bool {
	tld = strings.ToLower(tld)
	return tld == "jp" || strings.HasSuffix(tld, ".jp")
}

// Parse parses a JPRS WHOIS response.
func (p *JPParser) Parse(response string, domain string) (*whois.ParseResult, error) {
	result := &whois.ParseResult{
		Domain:     &whois.ParsedDomain{},
		Confidence: whois.ConfidenceHigh,
		ParserName: p.Name(),
	}

	pd := result.Domain
	pd.RawResponse = response

	// Check for "No match" or similar
	responseLower := strings.ToLower(response)
	if strings.Contains(responseLower, "no match") ||
		strings.Contains(responseLower, "not found") ||
		strings.Contains(responseLower, "no entries found") {
		result.Confidence = whois.ConfidenceLow
		result.Errors = append(result.Errors, "domain not found")
		pd.DomainName = strings.ToLower(domain)
		return result, nil
	}

	// Parse the response line by line
	for line := range strings.SplitSeq(response, "\n") {
		trimmedLine := strings.TrimSpace(line)

		// Skip empty lines and comments
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "[") && strings.HasSuffix(trimmedLine, "]") && !strings.Contains(trimmedLine, "ドメイン") && !strings.Contains(trimmedLine, "状態") {
			continue
		}

		// JPRS uses different formats:
		// 1. "key. [Japanese] value" - lettered keys
		// 2. "[Japanese] value" - bracketed keys
		p.parseLine(pd, trimmedLine)
	}

	// Ensure domain name is set
	if pd.DomainName == "" {
		pd.DomainName = strings.ToLower(domain)
	}

	return result, nil
}

// parseLine parses a single line from the WHOIS response.
func (p *JPParser) parseLine(pd *whois.ParsedDomain, line string) {
	// Try to extract key-value from JPRS format

	// Format 1: "X. [Japanese] VALUE" where X is a letter
	if len(line) > 2 && line[1] == '.' {
		key := string(line[0])
		rest := strings.TrimSpace(line[2:])

		// Skip Japanese label if present
		if idx := strings.Index(rest, "]"); idx > 0 && strings.HasPrefix(rest, "[") {
			rest = strings.TrimSpace(rest[idx+1:])
		}

		p.parseLetterKey(pd, key, rest)
		return
	}

	// Format 2: "[Japanese/English] VALUE"
	if strings.HasPrefix(line, "[") {
		closeBracket := strings.Index(line, "]")
		if closeBracket > 0 && closeBracket < len(line)-1 {
			key := line[1:closeBracket]
			value := strings.TrimSpace(line[closeBracket+1:])

			if value != "" {
				p.parseBracketKey(pd, key, value)
			}
		}
	}
}

// parseLetterKey parses fields with letter keys (a., b., c., etc.).
func (p *JPParser) parseLetterKey(pd *whois.ParsedDomain, key, value string) {
	if value == "" {
		return
	}

	switch strings.ToLower(key) {
	case "a": // Domain Name
		pd.DomainName = strings.ToLower(value)
	case "g": // Organization
		if pd.Registrant == nil {
			pd.Registrant = &whois.ParsedEntity{}
		}
		pd.Registrant.Organization = value
	case "m": // Registrant Contact Handle
		if pd.Registrant == nil {
			pd.Registrant = &whois.ParsedEntity{}
		}
		pd.Registrant.Handle = value
	case "n": // Technical Contact Handle
		if pd.TechContact == nil {
			pd.TechContact = &whois.ParsedEntity{}
		}
		pd.TechContact.Handle = value
	case "p": // Name Server
		ns := normalizeJPNameserver(value)
		if ns != "" {
			pd.Nameservers = append(pd.Nameservers, ns)
		}
	case "s": // DNSSEC Key
		if value != "" {
			signed := true
			pd.DNSSECSigned = &signed
		}
	}
}

// parseBracketKey parses fields with bracket keys.
func (p *JPParser) parseBracketKey(pd *whois.ParsedDomain, key, value string) {
	keyLower := strings.ToLower(key)

	switch {
	case strings.Contains(keyLower, "状態") || strings.Contains(keyLower, "state") || strings.Contains(keyLower, "status"):
		pd.Status = append(pd.Status, value)
	case strings.Contains(keyLower, "登録年月日") || strings.Contains(keyLower, "registered date") || strings.Contains(keyLower, "created"):
		if t := parseJPDate(value); t != nil {
			pd.CreatedDate = t
		}
	case strings.Contains(keyLower, "有効期限") || strings.Contains(keyLower, "expiration") || strings.Contains(keyLower, "expires"):
		if t := parseJPDate(value); t != nil {
			pd.ExpirationDate = t
		}
	case strings.Contains(keyLower, "最終更新") || strings.Contains(keyLower, "last update") || strings.Contains(keyLower, "updated"):
		if t := parseJPDate(value); t != nil {
			pd.UpdatedDate = t
		}
	case strings.Contains(keyLower, "ネームサーバ") || strings.Contains(keyLower, "name server"):
		ns := normalizeJPNameserver(value)
		if ns != "" {
			pd.Nameservers = append(pd.Nameservers, ns)
		}
	}
}

// parseJPDate parses dates in JPRS format (YYYY/MM/DD or YYYY/MM/DD HH:MM:SS (JST)).
func parseJPDate(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	// Remove timezone suffix like "(JST)"
	if idx := strings.Index(s, "("); idx > 0 {
		s = strings.TrimSpace(s[:idx])
	}

	formats := []string{
		"2006/01/02 15:04:05",
		"2006/01/02",
		"2006-01-02 15:04:05",
		"2006-01-02",
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

// normalizeJPNameserver normalizes a nameserver name.
func normalizeJPNameserver(ns string) string {
	ns = strings.TrimSpace(ns)
	ns = strings.ToLower(ns)
	ns = strings.TrimSuffix(ns, ".")

	// Must contain at least one dot
	if !strings.Contains(ns, ".") {
		return ""
	}

	// Remove any IP address that may follow
	if idx := strings.Index(ns, " "); idx > 0 {
		ns = ns[:idx]
	}

	return ns
}
