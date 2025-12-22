package schema

import (
	openrdap "github.com/openrdap/rdap"
)

// SimpleASN represents a simplified ASN response.
type SimpleASN struct {
	ASN          uint32           `json:"asn"`
	StartASN     uint32           `json:"start_asn,omitempty"`
	EndASN       uint32           `json:"end_asn,omitempty"`
	Name         string           `json:"name,omitempty"`
	Type         string           `json:"type,omitempty"`
	Country      string           `json:"country,omitempty"`
	Handle       string           `json:"handle,omitempty"`
	Status       []string         `json:"status,omitempty"`
	Registrant   *SimpleEntity    `json:"registrant,omitempty"`
	AdminContact *SimpleEntity    `json:"admin_contact,omitempty"`
	TechContact  *SimpleEntity    `json:"tech_contact,omitempty"`
	AbuseContact *SimpleEntity    `json:"abuse_contact,omitempty"`
	CreatedDate  string           `json:"created_date,omitempty"`
	UpdatedDate  string           `json:"updated_date,omitempty"`
	RDAPServer   string           `json:"rdap_server,omitempty"`
	Raw          *openrdap.Autnum `json:"-"`
}

// TransformASN transforms an RDAP ASN response to a simplified ASN.
func TransformASN(resp *openrdap.Autnum, rdapServer string) *SimpleASN {
	if resp == nil {
		return nil
	}

	asn := &SimpleASN{
		Name:       resp.Name,
		Type:       resp.Type,
		Country:    resp.Country,
		Handle:     resp.Handle,
		Status:     resp.Status,
		RDAPServer: rdapServer,
		Raw:        resp,
	}

	// Extract ASN values from pointers
	if resp.StartAutnum != nil {
		asn.StartASN = *resp.StartAutnum
		asn.ASN = *resp.StartAutnum
	}
	if resp.EndAutnum != nil {
		asn.EndASN = *resp.EndAutnum
	}

	// If start and end are the same, it's a single ASN - clear the range fields
	if asn.StartASN == asn.EndASN {
		asn.StartASN = 0
		asn.EndASN = 0
	}

	// Extract dates from events
	for _, event := range resp.Events {
		switch event.Action {
		case "registration":
			asn.CreatedDate = formatEventDate(event.Date)
		case "last changed":
			asn.UpdatedDate = formatEventDate(event.Date)
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
				asn.Registrant = entity
			case "administrative":
				asn.AdminContact = entity
			case "technical":
				asn.TechContact = entity
			case "abuse":
				asn.AbuseContact = entity
			}
		}

		// Extract country from entity if not set at ASN level
		if asn.Country == "" && entity.Country != "" {
			asn.Country = entity.Country
		}
	}

	return asn
}
