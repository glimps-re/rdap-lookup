package whois

import (
	"time"

	"github.com/glimps-re/rdap-lookup/internal/schema"
)

// TransformToSimpleDomain converts a ParseResult to a SimpleDomain.
// This allows WHOIS data to be returned in the same format as RDAP data.
func TransformToSimpleDomain(result *ParseResult) *schema.SimpleDomain {
	if result == nil || result.Domain == nil {
		return nil
	}

	pd := result.Domain

	domain := &schema.SimpleDomain{
		Name:        pd.DomainName,
		UnicodeName: pd.UnicodeName,
		Status:      pd.Status,
		DataSource:  string(DataSourceWHOIS),
		WHOISServer: pd.WHOISServer,
		Confidence:  string(result.Confidence),
	}

	// Convert dates to RFC3339 format
	if pd.CreatedDate != nil {
		domain.CreatedDate = formatTime(pd.CreatedDate)
	}
	if pd.UpdatedDate != nil {
		domain.UpdatedDate = formatTime(pd.UpdatedDate)
	}
	if pd.ExpirationDate != nil {
		domain.ExpirationDate = formatTime(pd.ExpirationDate)
	}

	// Convert contacts
	if pd.Registrar != nil {
		domain.Registrar = transformEntity(pd.Registrar)
	}
	if pd.Registrant != nil {
		domain.Registrant = transformEntity(pd.Registrant)
	}
	if pd.AdminContact != nil {
		domain.AdminContact = transformEntity(pd.AdminContact)
	}
	if pd.TechContact != nil {
		domain.TechContact = transformEntity(pd.TechContact)
	}

	// Convert nameservers
	for _, ns := range pd.Nameservers {
		domain.Nameservers = append(domain.Nameservers, schema.SimpleNS{
			Name: ns,
		})
	}

	// Convert DNSSEC info
	if pd.DNSSECSigned != nil {
		domain.DNSSEC = &schema.SimpleDNSSEC{
			Signed:           *pd.DNSSECSigned,
			DelegationSigned: *pd.DNSSECSigned,
		}
	}

	return domain
}

// transformEntity converts a ParsedEntity to a SimpleEntity.
func transformEntity(pe *ParsedEntity) *schema.SimpleEntity {
	if pe == nil {
		return nil
	}

	entity := &schema.SimpleEntity{
		Handle:       pe.Handle,
		Name:         pe.Name,
		Organization: pe.Organization,
		Email:        pe.Email,
		Phone:        pe.Phone,
		Country:      pe.Country,
	}

	// Build address from components if individual components are available,
	// otherwise use the pre-formatted address.
	if pe.Address != "" {
		entity.Address = pe.Address
	} else {
		entity.Address = buildAddress(pe)
	}

	return entity
}

// buildAddress builds a formatted address from entity components.
func buildAddress(pe *ParsedEntity) string {
	var parts []string

	if pe.Street != "" {
		parts = append(parts, pe.Street)
	}
	if pe.City != "" {
		parts = append(parts, pe.City)
	}
	if pe.State != "" {
		parts = append(parts, pe.State)
	}
	if pe.PostalCode != "" {
		parts = append(parts, pe.PostalCode)
	}
	if pe.Country != "" {
		parts = append(parts, pe.Country)
	}

	if len(parts) == 0 {
		return ""
	}

	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result += ", " + parts[i]
	}
	return result
}

// formatTime formats a time pointer to RFC3339 string in UTC.
func formatTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
