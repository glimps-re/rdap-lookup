package schema

import (
	"github.com/glimps-re/rdap-lookup/internal/rdap"
)

// SimpleEntityFull represents a full simplified entity response (for entity queries).
type SimpleEntityFull struct {
	Handle        string               `json:"handle"`
	Name          string               `json:"name,omitempty"`
	Organization  string               `json:"organization,omitempty"`
	Email         string               `json:"email,omitempty"`
	Phone         string               `json:"phone,omitempty"`
	Address       string               `json:"address,omitempty"`
	Country       string               `json:"country,omitempty"`
	Roles         []string             `json:"roles,omitempty"`
	Status        []string             `json:"status,omitempty"`
	CreatedDate   string               `json:"created_date,omitempty"`
	UpdatedDate   string               `json:"updated_date,omitempty"`
	RelatedIPNets []SimpleIPSummary    `json:"related_ip_networks,omitempty"`
	RelatedASNs   []SimpleASNSummary   `json:"related_asns,omitempty"`
	RDAPServer    string               `json:"rdap_server,omitempty"`
	Raw           *rdap.EntityResponse `json:"-"`
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
func TransformEntityResponse(resp *rdap.EntityResponse, rdapServer string) *SimpleEntityFull {
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

	// Parse vCard if available
	if len(resp.VCardArray) > 0 {
		contact := ParseVCard(resp.VCardArray)
		entity.Name = contact.Name
		entity.Organization = contact.Organization
		entity.Email = contact.Email
		entity.Phone = contact.Phone
		entity.Address = contact.Address
		entity.Country = contact.Country
	}

	// Extract dates from events
	for _, event := range resp.Events {
		switch event.EventAction {
		case "registration":
			entity.CreatedDate = formatEventDate(event.EventDate)
		case "last changed":
			entity.UpdatedDate = formatEventDate(event.EventDate)
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
			ASN:     autnum.StartAutnum,
			Handle:  autnum.Handle,
			Name:    autnum.Name,
			Country: autnum.Country,
		}
		entity.RelatedASNs = append(entity.RelatedASNs, summary)
	}

	return entity
}
