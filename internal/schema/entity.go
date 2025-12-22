package schema

import (
	openrdap "github.com/openrdap/rdap"
)

// SimpleEntityFull represents a full simplified entity response (for entity queries).
type SimpleEntityFull struct {
	Handle        string             `json:"handle"`
	Name          string             `json:"name,omitempty"`
	Organization  string             `json:"organization,omitempty"`
	Email         string             `json:"email,omitempty"`
	Phone         string             `json:"phone,omitempty"`
	Address       string             `json:"address,omitempty"`
	Country       string             `json:"country,omitempty"`
	Roles         []string           `json:"roles,omitempty"`
	Status        []string           `json:"status,omitempty"`
	CreatedDate   string             `json:"created_date,omitempty"`
	UpdatedDate   string             `json:"updated_date,omitempty"`
	RelatedIPNets []SimpleIPSummary  `json:"related_ip_networks,omitempty"`
	RelatedASNs   []SimpleASNSummary `json:"related_asns,omitempty"`
	RDAPServer    string             `json:"rdap_server,omitempty"`
	Raw           *openrdap.Entity   `json:"-"`
}

// SimpleIPSummary represents a summary of an IP network related to an entity.
type SimpleIPSummary struct {
	Handle       string `json:"handle,omitempty"`
	StartAddress string `json:"start_address,omitempty"`
	EndAddress   string `json:"end_address,omitempty"`
	Name         string `json:"name,omitempty"`
	Country      string `json:"country,omitempty"`
}

// SimpleASNSummary represents a summary of an ASN related to an entity.
type SimpleASNSummary struct {
	ASN     uint32 `json:"asn,omitempty"`
	Handle  string `json:"handle,omitempty"`
	Name    string `json:"name,omitempty"`
	Country string `json:"country,omitempty"`
}

// TransformEntityResponse transforms an RDAP entity response to a simplified entity.
func TransformEntityResponse(resp *openrdap.Entity, rdapServer string) *SimpleEntityFull {
	if resp == nil {
		return nil
	}

	entity := &SimpleEntityFull{
		Handle:     resp.Handle,
		Roles:      resp.Roles,
		Status:     resp.Status,
		RDAPServer: rdapServer,
		Raw:        resp,
	}

	// Extract contact info from VCard if available
	if resp.VCard != nil {
		entity.Name = resp.VCard.Name()
		entity.Organization = getVCardFirstValue(resp.VCard, "org")
		entity.Email = resp.VCard.Email()
		entity.Phone = resp.VCard.Tel()
		entity.Country = resp.VCard.Country()
		entity.Address = buildAddress(resp.VCard)
	}

	// Extract dates from events
	for _, event := range resp.Events {
		switch event.Action {
		case "registration":
			entity.CreatedDate = formatEventDate(event.Date)
		case "last changed":
			entity.UpdatedDate = formatEventDate(event.Date)
		}
	}

	// Extract related IP networks
	for _, network := range resp.Networks {
		summary := SimpleIPSummary{
			Handle:       network.Handle,
			StartAddress: network.StartAddress,
			EndAddress:   network.EndAddress,
			Name:         network.Name,
			Country:      network.Country,
		}
		entity.RelatedIPNets = append(entity.RelatedIPNets, summary)
	}

	// Extract related ASNs
	for _, autnum := range resp.Autnums {
		summary := SimpleASNSummary{
			Handle:  autnum.Handle,
			Name:    autnum.Name,
			Country: autnum.Country,
		}
		if autnum.StartAutnum != nil {
			summary.ASN = *autnum.StartAutnum
		}
		entity.RelatedASNs = append(entity.RelatedASNs, summary)
	}

	return entity
}
