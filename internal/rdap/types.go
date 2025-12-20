package rdap

import "time"

// Common RDAP structures shared across response types.

// Link represents an RDAP link object.
type Link struct {
	Value    string `json:"value,omitempty"`
	Rel      string `json:"rel,omitempty"`
	Href     string `json:"href,omitempty"`
	HrefLang string `json:"hreflang,omitempty"`
	Title    string `json:"title,omitempty"`
	Media    string `json:"media,omitempty"`
	Type     string `json:"type,omitempty"`
}

// Notice represents an RDAP notice or remark.
type Notice struct {
	Title       string   `json:"title,omitempty"`
	Type        string   `json:"type,omitempty"`
	Description []string `json:"description,omitempty"`
	Links       []Link   `json:"links,omitempty"`
}

// Event represents an RDAP event (registration, expiration, etc.).
type Event struct {
	EventAction string `json:"eventAction,omitempty"`
	EventDate   string `json:"eventDate,omitempty"`
	EventActor  string `json:"eventActor,omitempty"`
	Links       []Link `json:"links,omitempty"`
}

// ParsedEventDate attempts to parse the event date.
func (e *Event) ParsedEventDate() (time.Time, error) {
	return time.Parse(time.RFC3339, e.EventDate)
}

// PublicID represents a public identifier.
type PublicID struct {
	Type       string `json:"type,omitempty"`
	Identifier string `json:"identifier,omitempty"`
}

// Status represents RDAP status values.
type Status []string

// Contains checks if the status list contains a specific status.
func (s Status) Contains(status string) bool {
	for _, v := range s {
		if v == status {
			return true
		}
	}
	return false
}

// VCard represents a jCard/vCard structure for contact information.
// jCard is an array format: [["vcard", [properties...]]]
type VCard []any

// Entity represents an RDAP entity (registrar, registrant, etc.).
type Entity struct {
	ObjectClassName string     `json:"objectClassName,omitempty"`
	Handle          string     `json:"handle,omitempty"`
	VCardArray      []any      `json:"vcardArray,omitempty"`
	Roles           []string   `json:"roles,omitempty"`
	PublicIDs       []PublicID `json:"publicIds,omitempty"`
	Entities        []Entity   `json:"entities,omitempty"`
	Remarks         []Notice   `json:"remarks,omitempty"`
	Links           []Link     `json:"links,omitempty"`
	Events          []Event    `json:"events,omitempty"`
	Status          Status     `json:"status,omitempty"`
	Port43          string     `json:"port43,omitempty"`
}

// DomainResponse represents the RDAP response for a domain query.
type DomainResponse struct {
	ObjectClassName string   `json:"objectClassName,omitempty"`
	Handle          string   `json:"handle,omitempty"`
	LDHName         string   `json:"ldhName,omitempty"`
	UnicodeName     string   `json:"unicodeName,omitempty"`
	Status          Status   `json:"status,omitempty"`
	Entities        []Entity `json:"entities,omitempty"`
	Events          []Event  `json:"events,omitempty"`
	Links           []Link   `json:"links,omitempty"`
	Remarks         []Notice `json:"remarks,omitempty"`
	Notices         []Notice `json:"notices,omitempty"`
	Port43          string   `json:"port43,omitempty"`

	// Nameservers
	Nameservers []Nameserver `json:"nameservers,omitempty"`

	// SecureDNS information
	SecureDNS *SecureDNS `json:"secureDNS,omitempty"`

	// Network and rdapConformance
	RDAPConformance []string `json:"rdapConformance,omitempty"`

	// Variants (for IDN domains)
	Variants []Variant `json:"variants,omitempty"`

	// PublicIDs
	PublicIDs []PublicID `json:"publicIds,omitempty"`
}

// Nameserver represents nameserver information in a domain response.
type Nameserver struct {
	ObjectClassName string   `json:"objectClassName,omitempty"`
	Handle          string   `json:"handle,omitempty"`
	LDHName         string   `json:"ldhName,omitempty"`
	UnicodeName     string   `json:"unicodeName,omitempty"`
	Status          Status   `json:"status,omitempty"`
	IPAddresses     *IPAddrs `json:"ipAddresses,omitempty"`
	Remarks         []Notice `json:"remarks,omitempty"`
	Links           []Link   `json:"links,omitempty"`
	Events          []Event  `json:"events,omitempty"`
	Port43          string   `json:"port43,omitempty"`
}

// IPAddrs represents IP addresses for a nameserver.
type IPAddrs struct {
	V4 []string `json:"v4,omitempty"`
	V6 []string `json:"v6,omitempty"`
}

// SecureDNS represents DNSSEC information.
type SecureDNS struct {
	ZoneSigned       *bool     `json:"zoneSigned,omitempty"`
	DelegationSigned *bool     `json:"delegationSigned,omitempty"`
	MaxSigLife       int       `json:"maxSigLife,omitempty"`
	DSData           []DSData  `json:"dsData,omitempty"`
	KeyData          []KeyData `json:"keyData,omitempty"`
}

// DSData represents DNSSEC DS record data.
type DSData struct {
	KeyTag     int     `json:"keyTag,omitempty"`
	Algorithm  int     `json:"algorithm,omitempty"`
	DigestType int     `json:"digestType,omitempty"`
	Digest     string  `json:"digest,omitempty"`
	Links      []Link  `json:"links,omitempty"`
	Events     []Event `json:"events,omitempty"`
}

// KeyData represents DNSSEC key data.
type KeyData struct {
	Flags     int     `json:"flags,omitempty"`
	Protocol  int     `json:"protocol,omitempty"`
	Algorithm int     `json:"algorithm,omitempty"`
	PublicKey string  `json:"publicKey,omitempty"`
	Links     []Link  `json:"links,omitempty"`
	Events    []Event `json:"events,omitempty"`
}

// Variant represents an IDN variant.
type Variant struct {
	Relation     []string      `json:"relation,omitempty"`
	IDNTable     string        `json:"idnTable,omitempty"`
	VariantNames []VariantName `json:"variantNames,omitempty"`
}

// VariantName represents a variant name.
type VariantName struct {
	LDHName     string `json:"ldhName,omitempty"`
	UnicodeName string `json:"unicodeName,omitempty"`
}

// IPResponse represents the RDAP response for an IP network query.
type IPResponse struct {
	ObjectClassName string   `json:"objectClassName,omitempty"`
	Handle          string   `json:"handle,omitempty"`
	StartAddress    string   `json:"startAddress,omitempty"`
	EndAddress      string   `json:"endAddress,omitempty"`
	IPVersion       string   `json:"ipVersion,omitempty"`
	Name            string   `json:"name,omitempty"`
	Type            string   `json:"type,omitempty"`
	Country         string   `json:"country,omitempty"`
	ParentHandle    string   `json:"parentHandle,omitempty"`
	Status          Status   `json:"status,omitempty"`
	Entities        []Entity `json:"entities,omitempty"`
	Events          []Event  `json:"events,omitempty"`
	Links           []Link   `json:"links,omitempty"`
	Remarks         []Notice `json:"remarks,omitempty"`
	Notices         []Notice `json:"notices,omitempty"`
	Port43          string   `json:"port43,omitempty"`
	RDAPConformance []string `json:"rdapConformance,omitempty"`
	CIDR0Cidrs      []CIDR   `json:"cidr0_cidrs,omitempty"`
}

// CIDR represents a CIDR block.
type CIDR struct {
	V4Prefix string `json:"v4prefix,omitempty"`
	V6Prefix string `json:"v6prefix,omitempty"`
	Length   int    `json:"length,omitempty"`
}

// ASNResponse represents the RDAP response for an ASN query.
type ASNResponse struct {
	ObjectClassName string   `json:"objectClassName,omitempty"`
	Handle          string   `json:"handle,omitempty"`
	StartAutnum     uint32   `json:"startAutnum,omitempty"`
	EndAutnum       uint32   `json:"endAutnum,omitempty"`
	Name            string   `json:"name,omitempty"`
	Type            string   `json:"type,omitempty"`
	Country         string   `json:"country,omitempty"`
	Status          Status   `json:"status,omitempty"`
	Entities        []Entity `json:"entities,omitempty"`
	Events          []Event  `json:"events,omitempty"`
	Links           []Link   `json:"links,omitempty"`
	Remarks         []Notice `json:"remarks,omitempty"`
	Notices         []Notice `json:"notices,omitempty"`
	Port43          string   `json:"port43,omitempty"`
	RDAPConformance []string `json:"rdapConformance,omitempty"`
}

// EntityResponse represents the RDAP response for an entity query.
type EntityResponse struct {
	ObjectClassName string        `json:"objectClassName,omitempty"`
	Handle          string        `json:"handle,omitempty"`
	VCardArray      []any         `json:"vcardArray,omitempty"`
	Roles           []string      `json:"roles,omitempty"`
	PublicIDs       []PublicID    `json:"publicIds,omitempty"`
	Entities        []Entity      `json:"entities,omitempty"`
	Events          []Event       `json:"events,omitempty"`
	Links           []Link        `json:"links,omitempty"`
	Remarks         []Notice      `json:"remarks,omitempty"`
	Notices         []Notice      `json:"notices,omitempty"`
	Status          Status        `json:"status,omitempty"`
	Port43          string        `json:"port43,omitempty"`
	RDAPConformance []string      `json:"rdapConformance,omitempty"`
	AsEventActor    []Event       `json:"asEventActor,omitempty"`
	Networks        []IPResponse  `json:"networks,omitempty"`
	Autnums         []ASNResponse `json:"autnums,omitempty"`
}

// NameserverResponse represents the RDAP response for a nameserver query.
type NameserverResponse struct {
	ObjectClassName string   `json:"objectClassName,omitempty"`
	Handle          string   `json:"handle,omitempty"`
	LDHName         string   `json:"ldhName,omitempty"`
	UnicodeName     string   `json:"unicodeName,omitempty"`
	Status          Status   `json:"status,omitempty"`
	IPAddresses     *IPAddrs `json:"ipAddresses,omitempty"`
	Entities        []Entity `json:"entities,omitempty"`
	Events          []Event  `json:"events,omitempty"`
	Links           []Link   `json:"links,omitempty"`
	Remarks         []Notice `json:"remarks,omitempty"`
	Notices         []Notice `json:"notices,omitempty"`
	Port43          string   `json:"port43,omitempty"`
	RDAPConformance []string `json:"rdapConformance,omitempty"`
}
