package schema

import (
	"time"

	"github.com/glimps-re/rdap-lookup/internal/rdap"
)

// SimpleDomain represents a simplified domain response.
type SimpleDomain struct {
	Name           string               `json:"name"`
	UnicodeName    string               `json:"unicode_name,omitempty"`
	Status         []string             `json:"status,omitempty"`
	Registrar      *SimpleEntity        `json:"registrar,omitempty"`
	Registrant     *SimpleEntity        `json:"registrant,omitempty"`
	AdminContact   *SimpleEntity        `json:"admin_contact,omitempty"`
	TechContact    *SimpleEntity        `json:"tech_contact,omitempty"`
	Nameservers    []SimpleNS           `json:"nameservers,omitempty"`
	CreatedDate    string               `json:"created_date,omitempty"`
	UpdatedDate    string               `json:"updated_date,omitempty"`
	ExpirationDate string               `json:"expiration_date,omitempty"`
	DNSSEC         *SimpleDNSSEC        `json:"dnssec,omitempty"`
	RDAPServer     string               `json:"rdap_server,omitempty"`
	Raw            *rdap.DomainResponse `json:"-"`
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
func TransformDomain(resp *rdap.DomainResponse, rdapServer string) *SimpleDomain {
	if resp == nil {
		return nil
	}

	domain := &SimpleDomain{
		Name:        resp.LDHName,
		UnicodeName: resp.UnicodeName,
		Status:      resp.Status,
		RDAPServer:  rdapServer,
		Raw:         resp,
	}

	// Extract dates from events
	for _, event := range resp.Events {
		switch event.EventAction {
		case "registration":
			domain.CreatedDate = formatEventDate(event.EventDate)
		case "last changed", "last update of RDAP database":
			if domain.UpdatedDate == "" {
				domain.UpdatedDate = formatEventDate(event.EventDate)
			}
		case "expiration":
			domain.ExpirationDate = formatEventDate(event.EventDate)
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
func transformEntity(entity *rdap.Entity) *SimpleEntity {
	if entity == nil {
		return nil
	}

	simple := &SimpleEntity{
		Handle: entity.Handle,
		Roles:  entity.Roles,
	}

	// Parse vCard if available
	if len(entity.VCardArray) > 0 {
		contact := ParseVCard(entity.VCardArray)
		simple.Name = contact.Name
		simple.Organization = contact.Organization
		simple.Email = contact.Email
		simple.Phone = contact.Phone
		simple.Address = contact.Address
		simple.Country = contact.Country
	}

	return simple
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
