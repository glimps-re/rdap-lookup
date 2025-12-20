package rdaplookup

import (
	"fmt"
	"time"
)

// Raw RDAP response types for parsing upstream responses.
// These are internal types that get transformed to the simplified public types.

// rawLink represents an RDAP link object.
type rawLink struct {
	Value    string `json:"value,omitempty"`
	Rel      string `json:"rel,omitempty"`
	Href     string `json:"href,omitempty"`
	HrefLang string `json:"hreflang,omitempty"`
	Title    string `json:"title,omitempty"`
	Media    string `json:"media,omitempty"`
	Type     string `json:"type,omitempty"`
}

// rawNotice represents an RDAP notice or remark.
type rawNotice struct {
	Title       string    `json:"title,omitempty"`
	Type        string    `json:"type,omitempty"`
	Description []string  `json:"description,omitempty"`
	Links       []rawLink `json:"links,omitempty"`
}

// rawEvent represents an RDAP event.
type rawEvent struct {
	EventAction string    `json:"eventAction,omitempty"`
	EventDate   string    `json:"eventDate,omitempty"`
	EventActor  string    `json:"eventActor,omitempty"`
	Links       []rawLink `json:"links,omitempty"`
}

// rawPublicID represents a public identifier.
type rawPublicID struct {
	Type       string `json:"type,omitempty"`
	Identifier string `json:"identifier,omitempty"`
}

// rawEntity represents an RDAP entity.
type rawEntity struct {
	ObjectClassName string        `json:"objectClassName,omitempty"`
	Handle          string        `json:"handle,omitempty"`
	VCardArray      []any         `json:"vcardArray,omitempty"`
	Roles           []string      `json:"roles,omitempty"`
	PublicIDs       []rawPublicID `json:"publicIds,omitempty"`
	Entities        []rawEntity   `json:"entities,omitempty"`
	Remarks         []rawNotice   `json:"remarks,omitempty"`
	Links           []rawLink     `json:"links,omitempty"`
	Events          []rawEvent    `json:"events,omitempty"`
	Status          []string      `json:"status,omitempty"`
	Port43          string        `json:"port43,omitempty"`
}

// rawIPAddrs represents IP addresses for a nameserver.
type rawIPAddrs struct {
	V4 []string `json:"v4,omitempty"`
	V6 []string `json:"v6,omitempty"`
}

// rawNameserver represents nameserver information.
type rawNameserver struct {
	ObjectClassName string      `json:"objectClassName,omitempty"`
	Handle          string      `json:"handle,omitempty"`
	LDHName         string      `json:"ldhName,omitempty"`
	UnicodeName     string      `json:"unicodeName,omitempty"`
	Status          []string    `json:"status,omitempty"`
	IPAddresses     *rawIPAddrs `json:"ipAddresses,omitempty"`
	Remarks         []rawNotice `json:"remarks,omitempty"`
	Links           []rawLink   `json:"links,omitempty"`
	Events          []rawEvent  `json:"events,omitempty"`
	Port43          string      `json:"port43,omitempty"`
}

// rawSecureDNS represents DNSSEC information.
type rawSecureDNS struct {
	ZoneSigned       *bool        `json:"zoneSigned,omitempty"`
	DelegationSigned *bool        `json:"delegationSigned,omitempty"`
	MaxSigLife       int          `json:"maxSigLife,omitempty"`
	DSData           []rawDSData  `json:"dsData,omitempty"`
	KeyData          []rawKeyData `json:"keyData,omitempty"`
}

// rawDSData represents DNSSEC DS record data.
type rawDSData struct {
	KeyTag     int        `json:"keyTag,omitempty"`
	Algorithm  int        `json:"algorithm,omitempty"`
	DigestType int        `json:"digestType,omitempty"`
	Digest     string     `json:"digest,omitempty"`
	Links      []rawLink  `json:"links,omitempty"`
	Events     []rawEvent `json:"events,omitempty"`
}

// rawKeyData represents DNSSEC key data.
type rawKeyData struct {
	Flags     int        `json:"flags,omitempty"`
	Protocol  int        `json:"protocol,omitempty"`
	Algorithm int        `json:"algorithm,omitempty"`
	PublicKey string     `json:"publicKey,omitempty"`
	Links     []rawLink  `json:"links,omitempty"`
	Events    []rawEvent `json:"events,omitempty"`
}

// rawDomainResponse represents the RDAP response for a domain query.
type rawDomainResponse struct {
	ObjectClassName string          `json:"objectClassName,omitempty"`
	Handle          string          `json:"handle,omitempty"`
	LDHName         string          `json:"ldhName,omitempty"`
	UnicodeName     string          `json:"unicodeName,omitempty"`
	Status          []string        `json:"status,omitempty"`
	Entities        []rawEntity     `json:"entities,omitempty"`
	Events          []rawEvent      `json:"events,omitempty"`
	Links           []rawLink       `json:"links,omitempty"`
	Remarks         []rawNotice     `json:"remarks,omitempty"`
	Notices         []rawNotice     `json:"notices,omitempty"`
	Port43          string          `json:"port43,omitempty"`
	Nameservers     []rawNameserver `json:"nameservers,omitempty"`
	SecureDNS       *rawSecureDNS   `json:"secureDNS,omitempty"`
	RDAPConformance []string        `json:"rdapConformance,omitempty"`
	PublicIDs       []rawPublicID   `json:"publicIds,omitempty"`
}

// rawCIDR represents a CIDR block.
type rawCIDR struct {
	V4Prefix string `json:"v4prefix,omitempty"`
	V6Prefix string `json:"v6prefix,omitempty"`
	Length   int    `json:"length,omitempty"`
}

// rawIPResponse represents the RDAP response for an IP network query.
type rawIPResponse struct {
	ObjectClassName string      `json:"objectClassName,omitempty"`
	Handle          string      `json:"handle,omitempty"`
	StartAddress    string      `json:"startAddress,omitempty"`
	EndAddress      string      `json:"endAddress,omitempty"`
	IPVersion       string      `json:"ipVersion,omitempty"`
	Name            string      `json:"name,omitempty"`
	Type            string      `json:"type,omitempty"`
	Country         string      `json:"country,omitempty"`
	ParentHandle    string      `json:"parentHandle,omitempty"`
	Status          []string    `json:"status,omitempty"`
	Entities        []rawEntity `json:"entities,omitempty"`
	Events          []rawEvent  `json:"events,omitempty"`
	Links           []rawLink   `json:"links,omitempty"`
	Remarks         []rawNotice `json:"remarks,omitempty"`
	Notices         []rawNotice `json:"notices,omitempty"`
	Port43          string      `json:"port43,omitempty"`
	RDAPConformance []string    `json:"rdapConformance,omitempty"`
	CIDR0Cidrs      []rawCIDR   `json:"cidr0_cidrs,omitempty"`
}

// rawASNResponse represents the RDAP response for an ASN query.
type rawASNResponse struct {
	ObjectClassName string      `json:"objectClassName,omitempty"`
	Handle          string      `json:"handle,omitempty"`
	StartAutnum     uint32      `json:"startAutnum,omitempty"`
	EndAutnum       uint32      `json:"endAutnum,omitempty"`
	Name            string      `json:"name,omitempty"`
	Type            string      `json:"type,omitempty"`
	Country         string      `json:"country,omitempty"`
	Status          []string    `json:"status,omitempty"`
	Entities        []rawEntity `json:"entities,omitempty"`
	Events          []rawEvent  `json:"events,omitempty"`
	Links           []rawLink   `json:"links,omitempty"`
	Remarks         []rawNotice `json:"remarks,omitempty"`
	Notices         []rawNotice `json:"notices,omitempty"`
	Port43          string      `json:"port43,omitempty"`
	RDAPConformance []string    `json:"rdapConformance,omitempty"`
}

// rawEntityResponse represents the RDAP response for an entity query.
type rawEntityResponse struct {
	ObjectClassName string           `json:"objectClassName,omitempty"`
	Handle          string           `json:"handle,omitempty"`
	VCardArray      []any            `json:"vcardArray,omitempty"`
	Roles           []string         `json:"roles,omitempty"`
	PublicIDs       []rawPublicID    `json:"publicIds,omitempty"`
	Entities        []rawEntity      `json:"entities,omitempty"`
	Events          []rawEvent       `json:"events,omitempty"`
	Links           []rawLink        `json:"links,omitempty"`
	Remarks         []rawNotice      `json:"remarks,omitempty"`
	Notices         []rawNotice      `json:"notices,omitempty"`
	Status          []string         `json:"status,omitempty"`
	Port43          string           `json:"port43,omitempty"`
	RDAPConformance []string         `json:"rdapConformance,omitempty"`
	Networks        []rawIPResponse  `json:"networks,omitempty"`
	Autnums         []rawASNResponse `json:"autnums,omitempty"`
}

// Transformation functions

func transformDomainResponse(raw *rawDomainResponse, rdapServer string) *DomainResponse {
	if raw == nil {
		return nil
	}

	resp := &DomainResponse{
		Name:        raw.LDHName,
		Status:      raw.Status,
		Nameservers: make([]SimpleNS, 0, len(raw.Nameservers)),
		RDAPServer:  rdapServer + "domain/" + raw.LDHName,
	}

	// Extract dates from events
	for _, event := range raw.Events {
		dateStr := formatEventDateStr(event.EventDate)
		switch event.EventAction {
		case "registration":
			resp.CreatedDate = dateStr
		case "last changed", "last update of RDAP database":
			if resp.UpdatedDate == "" {
				resp.UpdatedDate = dateStr
			}
		case "expiration":
			resp.ExpirationDate = dateStr
		}
	}

	// Extract registrar
	for i := range raw.Entities {
		entity := &raw.Entities[i]
		for _, role := range entity.Roles {
			if role == "registrar" {
				resp.Registrar = transformRawEntityToSimpleContact(entity)
				break
			}
		}
	}

	// Extract contacts
	for i := range raw.Entities {
		entity := &raw.Entities[i]
		for _, role := range entity.Roles {
			switch role {
			case "registrant":
				resp.Registrant = transformRawEntityToSimpleContact(entity)
			case "administrative":
				resp.AdminContact = transformRawEntityToSimpleContact(entity)
			case "technical":
				resp.TechContact = transformRawEntityToSimpleContact(entity)
			}
		}
	}

	// Extract nameservers
	for _, ns := range raw.Nameservers {
		if ns.LDHName != "" {
			simpleNS := SimpleNS{
				Name:        ns.LDHName,
				UnicodeName: ns.UnicodeName,
			}
			if ns.IPAddresses != nil {
				simpleNS.IPv4 = ns.IPAddresses.V4
				simpleNS.IPv6 = ns.IPAddresses.V6
			}
			resp.Nameservers = append(resp.Nameservers, simpleNS)
		}
	}

	// Extract DNSSEC info
	if raw.SecureDNS != nil {
		resp.DNSSEC = &SimpleDNSSEC{}
		if raw.SecureDNS.DelegationSigned != nil {
			resp.DNSSEC.DelegationSigned = *raw.SecureDNS.DelegationSigned
		}
		if raw.SecureDNS.ZoneSigned != nil {
			resp.DNSSEC.Signed = *raw.SecureDNS.ZoneSigned
		}
	}

	// Try to extract country from registrant
	if resp.Registrant != nil && resp.Registrant.Country != "" {
		resp.Country = resp.Registrant.Country
	}

	return resp
}

func transformIPResponse(raw *rawIPResponse, rdapServer string) *IPResponse {
	if raw == nil {
		return nil
	}

	resp := &IPResponse{
		StartAddress: raw.StartAddress,
		EndAddress:   raw.EndAddress,
		Handle:       raw.Handle,
		Name:         raw.Name,
		Type:         raw.Type,
		Country:      raw.Country,
		ParentHandle: raw.ParentHandle,
		Status:       raw.Status,
		RDAPServer:   rdapServer + "ip/" + raw.StartAddress,
	}

	// Build CIDR list
	for _, cidr := range raw.CIDR0Cidrs {
		if cidr.V4Prefix != "" {
			resp.CIDR = append(resp.CIDR, cidr.V4Prefix+"/"+formatInt(cidr.Length))
		}
		if cidr.V6Prefix != "" {
			resp.CIDR = append(resp.CIDR, cidr.V6Prefix+"/"+formatInt(cidr.Length))
		}
	}

	// Extract dates from events
	for _, event := range raw.Events {
		dateStr := formatEventDateStr(event.EventDate)
		switch event.EventAction {
		case "registration":
			resp.CreatedDate = dateStr
		case "last changed":
			if resp.UpdatedDate == "" {
				resp.UpdatedDate = dateStr
			}
		}
	}

	// Extract entities by role
	for i := range raw.Entities {
		entity := &raw.Entities[i]
		for _, role := range entity.Roles {
			contact := transformRawEntityToSimpleContact(entity)
			switch role {
			case "registrant":
				resp.Registrant = contact
			case "administrative":
				resp.AdminContact = contact
			case "technical":
				resp.TechContact = contact
			case "abuse":
				resp.AbuseContact = contact
			}
		}
	}

	return resp
}

func transformASNResponse(raw *rawASNResponse, rdapServer string) *ASNResponse {
	if raw == nil {
		return nil
	}

	resp := &ASNResponse{
		StartAutnum: raw.StartAutnum,
		EndAutnum:   raw.EndAutnum,
		Handle:      raw.Handle,
		Name:        raw.Name,
		Type:        raw.Type,
		Country:     raw.Country,
		Status:      raw.Status,
		RDAPServer:  rdapServer + "autnum/" + raw.Handle,
	}

	// Extract dates from events
	for _, event := range raw.Events {
		dateStr := formatEventDateStr(event.EventDate)
		switch event.EventAction {
		case "registration":
			resp.CreatedDate = dateStr
		case "last changed":
			if resp.UpdatedDate == "" {
				resp.UpdatedDate = dateStr
			}
		}
	}

	// Extract entities
	for i := range raw.Entities {
		entity := transformRawEntityToSimpleEntity(&raw.Entities[i])
		if entity != nil {
			resp.Entities = append(resp.Entities, *entity)
		}
	}

	return resp
}

func transformEntityResponse(raw *rawEntityResponse, rdapServer string) *EntityResponse {
	if raw == nil {
		return nil
	}

	resp := &EntityResponse{
		Handle:     raw.Handle,
		Roles:      raw.Roles,
		Status:     raw.Status,
		RDAPServer: rdapServer + "entity/" + raw.Handle,
	}

	// Parse vCard
	contact := parseVCardArray(raw.VCardArray)
	resp.Name = contact.name
	resp.Organization = contact.organization
	resp.Email = contact.email
	resp.Phone = contact.phone
	resp.Address = contact.address
	resp.Country = contact.country

	// Extract dates from events
	for _, event := range raw.Events {
		dateStr := formatEventDateStr(event.EventDate)
		switch event.EventAction {
		case "registration":
			resp.CreatedDate = dateStr
		case "last changed":
			if resp.UpdatedDate == "" {
				resp.UpdatedDate = dateStr
			}
		}
	}

	// Extract related IP networks
	for _, net := range raw.Networks {
		resp.RelatedIPNets = append(resp.RelatedIPNets, SimpleIPNet{
			Handle:       net.Handle,
			StartAddress: net.StartAddress,
			EndAddress:   net.EndAddress,
			Name:         net.Name,
			Country:      net.Country,
		})
	}

	// Extract related ASNs
	for _, asn := range raw.Autnums {
		resp.RelatedASNs = append(resp.RelatedASNs, SimpleASNEntry{
			ASN:     asn.StartAutnum,
			Handle:  asn.Handle,
			Name:    asn.Name,
			Country: asn.Country,
		})
	}

	return resp
}

func transformRawEntityToSimpleContact(entity *rawEntity) *SimpleContact {
	if entity == nil {
		return nil
	}

	contact := parseVCardArray(entity.VCardArray)

	return &SimpleContact{
		Name:         contact.name,
		Organization: contact.organization,
		Email:        contact.email,
		Phone:        contact.phone,
		Address:      contact.address,
		Country:      contact.country,
	}
}

func transformRawEntityToSimpleEntity(entity *rawEntity) *SimpleEntity {
	if entity == nil {
		return nil
	}

	contact := parseVCardArray(entity.VCardArray)

	return &SimpleEntity{
		Handle:       entity.Handle,
		Name:         contact.name,
		Organization: contact.organization,
		Email:        contact.email,
		Phone:        contact.phone,
		Roles:        entity.Roles,
		Country:      contact.country,
	}
}

func formatEventDateStr(dateStr string) string {
	if dateStr == "" {
		return ""
	}
	t, err := parseEventDate(dateStr)
	if err != nil {
		return dateStr
	}
	return t.UTC().Format(time.RFC3339)
}

func formatInt(n int) string {
	return fmt.Sprintf("%d", n)
}

func parseEventDate(dateStr string) (time.Time, error) {
	if dateStr == "" {
		return time.Time{}, nil
	}

	// Try RFC3339 first
	t, err := time.Parse(time.RFC3339, dateStr)
	if err == nil {
		return t.UTC(), nil
	}

	// Try other common formats
	formats := []string{
		"2006-01-02T15:04:05Z0700",
		"2006-01-02T15:04:05",
		"2006-01-02",
	}
	for _, format := range formats {
		if t, err = time.Parse(format, dateStr); err == nil {
			return t.UTC(), nil
		}
	}

	return time.Time{}, err
}

// vCardContact holds parsed vCard information.
type vCardContact struct {
	name         string
	organization string
	email        string
	phone        string
	address      string
	country      string
}

// parseVCardArray parses jCard/vCard array format.
// jCard format: ["vcard", [[property-name, params, type, value], ...]]
func parseVCardArray(vcardArray []any) vCardContact {
	var contact vCardContact

	if len(vcardArray) < 2 {
		return contact
	}

	properties, ok := vcardArray[1].([]any)
	if !ok {
		return contact
	}

	for _, prop := range properties {
		propArray, ok := prop.([]any)
		if !ok || len(propArray) < 4 {
			continue
		}

		propName, ok := propArray[0].(string)
		if !ok {
			continue
		}

		value := anyToString(propArray[3])

		switch propName {
		case "fn":
			contact.name = value
		case "org":
			contact.organization = value
		case "email":
			contact.email = value
		case "tel":
			contact.phone = value
		case "adr":
			// Address is an array, extract country (last element)
			if addrArray, ok := propArray[3].([]any); ok && len(addrArray) >= 7 {
				contact.country = anyToString(addrArray[6])
				// Build address from parts
				parts := make([]string, 0)
				for _, part := range addrArray {
					if s := anyToString(part); s != "" {
						parts = append(parts, s)
					}
				}
				if len(parts) > 0 {
					contact.address = parts[len(parts)-1] // Just country for now
				}
			}
		}
	}

	return contact
}

const maxVCardDepth = 10

func anyToString(v any) string {
	return anyToStringWithDepth(v, 0)
}

func anyToStringWithDepth(v any, depth int) string {
	if depth > maxVCardDepth {
		return ""
	}
	switch s := v.(type) {
	case string:
		return s
	case []any:
		if len(s) > 0 {
			return anyToStringWithDepth(s[0], depth+1)
		}
	}
	return ""
}
