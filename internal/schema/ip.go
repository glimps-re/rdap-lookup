package schema

import (
	"github.com/glimps-re/rdap-lookup/internal/rdap"
)

// SimpleIP represents a simplified IP network response.
type SimpleIP struct {
	StartAddress string           `json:"start_address"`
	EndAddress   string           `json:"end_address"`
	CIDR         []string         `json:"cidr,omitempty"`
	IPVersion    string           `json:"ip_version"`
	Name         string           `json:"name,omitempty"`
	Type         string           `json:"type,omitempty"`
	Country      string           `json:"country,omitempty"`
	Handle       string           `json:"handle,omitempty"`
	ParentHandle string           `json:"parent_handle,omitempty"`
	Status       []string         `json:"status,omitempty"`
	Registrant   *SimpleEntity    `json:"registrant,omitempty"`
	AdminContact *SimpleEntity    `json:"admin_contact,omitempty"`
	TechContact  *SimpleEntity    `json:"tech_contact,omitempty"`
	AbuseContact *SimpleEntity    `json:"abuse_contact,omitempty"`
	CreatedDate  string           `json:"created_date,omitempty"`
	UpdatedDate  string           `json:"updated_date,omitempty"`
	RDAPServer   string           `json:"rdap_server,omitempty"`
	Raw          *rdap.IPResponse `json:"-"`
}

// TransformIP transforms an RDAP IP response to a simplified IP.
func TransformIP(resp *rdap.IPResponse, rdapServer string) *SimpleIP {
	if resp == nil {
		return nil
	}

	ip := &SimpleIP{
		StartAddress: resp.StartAddress,
		EndAddress:   resp.EndAddress,
		IPVersion:    resp.IPVersion,
		Name:         resp.Name,
		Type:         resp.Type,
		Country:      resp.Country,
		Handle:       resp.Handle,
		ParentHandle: resp.ParentHandle,
		Status:       resp.Status,
		RDAPServer:   rdapServer,
		Raw:          resp,
	}

	// Extract CIDR blocks
	for _, cidr := range resp.CIDR0Cidrs {
		if cidr.V4Prefix != "" {
			ip.CIDR = append(ip.CIDR, formatCIDR(cidr.V4Prefix, cidr.Length))
		}
		if cidr.V6Prefix != "" {
			ip.CIDR = append(ip.CIDR, formatCIDR(cidr.V6Prefix, cidr.Length))
		}
	}

	// Extract dates from events
	for _, event := range resp.Events {
		switch event.EventAction {
		case "registration":
			ip.CreatedDate = formatEventDate(event.EventDate)
		case "last changed":
			ip.UpdatedDate = formatEventDate(event.EventDate)
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
			case "registrant":
				ip.Registrant = entity
			case "administrative":
				ip.AdminContact = entity
			case "technical":
				ip.TechContact = entity
			case "abuse":
				ip.AbuseContact = entity
			}
		}

		// Extract country from entity if not set at IP level
		if ip.Country == "" && entity.Country != "" {
			ip.Country = entity.Country
		}
	}

	return ip
}

// formatCIDR formats a CIDR block from prefix and length.
func formatCIDR(prefix string, length int) string {
	if length > 0 {
		return prefix + "/" + itoa(length)
	}
	return prefix
}

// itoa converts an integer to string without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}

	var neg bool
	if n < 0 {
		neg = true
		n = -n
	}

	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}

	if neg {
		i--
		buf[i] = '-'
	}

	return string(buf[i:])
}
