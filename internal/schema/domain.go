package schema

import (
	"strings"
	"time"

	openrdap "github.com/openrdap/rdap"
)

// SimpleDomain represents a simplified domain response.
type SimpleDomain struct {
	Name           string        `json:"name"`
	UnicodeName    string        `json:"unicode_name,omitempty"`
	Status         []string      `json:"status,omitempty"`
	Registrar      *SimpleEntity `json:"registrar,omitempty"`
	Registrant     *SimpleEntity `json:"registrant,omitempty"`
	AdminContact   *SimpleEntity `json:"admin_contact,omitempty"`
	TechContact    *SimpleEntity `json:"tech_contact,omitempty"`
	Nameservers    []SimpleNS    `json:"nameservers,omitempty"`
	CreatedDate    string        `json:"created_date,omitempty"`
	UpdatedDate    string        `json:"updated_date,omitempty"`
	ExpirationDate string        `json:"expiration_date,omitempty"`
	DNSSEC         *SimpleDNSSEC `json:"dnssec,omitempty"`

	// Source information
	DataSource  string `json:"data_source"`            // "rdap" or "whois"
	RDAPServer  string `json:"rdap_server,omitempty"`  // RDAP server URL (if source is rdap)
	WHOISServer string `json:"whois_server,omitempty"` // WHOIS server hostname (if source is whois)
	Confidence  string `json:"confidence,omitempty"`   // "high" or "low" (for whois only)

	Raw *openrdap.Domain `json:"-"`
}

// SimpleNS represents a simplified nameserver.
type SimpleNS struct {
	Name        string   `json:"name"`
	UnicodeName string   `json:"unicode_name,omitempty"`
	IPv4        []string `json:"ipv4,omitempty"`
	IPv6        []string `json:"ipv6,omitempty"`
}

// SimpleDNSSEC represents simplified DNSSEC information.
type SimpleDNSSEC struct {
	Signed           bool `json:"signed"`
	DelegationSigned bool `json:"delegation_signed"`
}

// SimpleEntity represents a simplified entity/contact.
type SimpleEntity struct {
	Handle       string   `json:"handle,omitempty"`
	Name         string   `json:"name,omitempty"`
	Organization string   `json:"organization,omitempty"`
	Email        string   `json:"email,omitempty"`
	Phone        string   `json:"phone,omitempty"`
	Address      string   `json:"address,omitempty"`
	Country      string   `json:"country,omitempty"`
	Roles        []string `json:"roles,omitempty"`
}

// TransformDomain transforms an RDAP domain response to a simplified domain.
func TransformDomain(resp *openrdap.Domain, rdapServer string) *SimpleDomain {
	if resp == nil {
		return nil
	}

	domain := &SimpleDomain{
		Name:        resp.LDHName,
		UnicodeName: resp.UnicodeName,
		Status:      resp.Status,
		DataSource:  "rdap",
		RDAPServer:  rdapServer,
		Raw:         resp,
	}

	// Extract dates from events
	for _, event := range resp.Events {
		switch event.Action {
		case "registration":
			domain.CreatedDate = formatEventDate(event.Date)
		case "last changed", "last update of RDAP database":
			if domain.UpdatedDate == "" {
				domain.UpdatedDate = formatEventDate(event.Date)
			}
		case "expiration":
			domain.ExpirationDate = formatEventDate(event.Date)
		}
	}

	// Extract entities by role
	for i := range resp.Entities {
		entity := transformEntity(&resp.Entities[i])
		if entity == nil {
			continue
		}

		for _, role := range resp.Entities[i].Roles {
			switch role {
			case "registrar":
				domain.Registrar = entity
			case "registrant":
				domain.Registrant = entity
			case "administrative":
				domain.AdminContact = entity
			case "technical":
				domain.TechContact = entity
			}
		}
	}

	// Extract nameservers
	for _, ns := range resp.Nameservers {
		simpleNS := SimpleNS{
			Name:        ns.LDHName,
			UnicodeName: ns.UnicodeName,
		}
		if ns.IPAddresses != nil {
			simpleNS.IPv4 = ns.IPAddresses.V4
			simpleNS.IPv6 = ns.IPAddresses.V6
		}
		domain.Nameservers = append(domain.Nameservers, simpleNS)
	}

	// Extract DNSSEC info
	if resp.SecureDNS != nil {
		domain.DNSSEC = &SimpleDNSSEC{}
		if resp.SecureDNS.ZoneSigned != nil {
			domain.DNSSEC.Signed = *resp.SecureDNS.ZoneSigned
		}
		if resp.SecureDNS.DelegationSigned != nil {
			domain.DNSSEC.DelegationSigned = *resp.SecureDNS.DelegationSigned
		}
	}

	return domain
}

// transformEntity transforms an RDAP entity to a simplified entity.
func transformEntity(entity *openrdap.Entity) *SimpleEntity {
	if entity == nil {
		return nil
	}

	simple := &SimpleEntity{
		Handle: entity.Handle,
		Roles:  entity.Roles,
	}

	// Extract contact info from VCard if available
	if entity.VCard != nil {
		simple.Name = entity.VCard.Name()
		simple.Organization = getVCardFirstValue(entity.VCard, "org")
		simple.Email = entity.VCard.Email()
		simple.Phone = entity.VCard.Tel()
		simple.Country = entity.VCard.Country()
		// Build address from components
		simple.Address = buildAddress(entity.VCard)
	}

	return simple
}

// buildAddress builds a formatted address from VCard components.
func buildAddress(vcard *openrdap.VCard) string {
	var parts []string

	if street := vcard.StreetAddress(); street != "" {
		parts = append(parts, street)
	}
	if locality := vcard.Locality(); locality != "" {
		parts = append(parts, locality)
	}
	if region := vcard.Region(); region != "" {
		parts = append(parts, region)
	}
	if postal := vcard.PostalCode(); postal != "" {
		parts = append(parts, postal)
	}
	if country := vcard.Country(); country != "" {
		parts = append(parts, country)
	}

	if len(parts) == 0 {
		return ""
	}

	result := parts[0]
	var resultSb186 strings.Builder
	for i := 1; i < len(parts); i++ {
		resultSb186.WriteString(", " + parts[i])
	}
	result += resultSb186.String()
	return result
}

// getVCardFirstValue retrieves the first value for a vCard property by name.
func getVCardFirstValue(vcard *openrdap.VCard, name string) string {
	prop := vcard.GetFirst(name)
	if prop == nil {
		return ""
	}
	values := prop.Values()
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// formatEventDate formats an event date string to a consistent format.
func formatEventDate(dateStr string) string {
	if dateStr == "" {
		return ""
	}

	// Try to parse and reformat to consistent format
	t, err := time.Parse(time.RFC3339, dateStr)
	if err != nil {
		// Try other common formats
		formats := []string{
			"2006-01-02T15:04:05Z0700",
			"2006-01-02T15:04:05",
			"2006-01-02",
		}
		for _, format := range formats {
			if t, err = time.Parse(format, dateStr); err == nil {
				break
			}
		}
	}

	if err != nil {
		// Return original if we can't parse it
		return dateStr
	}

	return t.UTC().Format(time.RFC3339)
}
