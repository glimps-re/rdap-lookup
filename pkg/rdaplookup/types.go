package rdaplookup

import "github.com/glimps-re/rdap-lookup/internal/schema"

// DomainResponse represents a simplified domain lookup response.
type DomainResponse struct {
	Name           string         `json:"name"`
	UnicodeName    string         `json:"unicode_name,omitempty"`
	Status         []string       `json:"status,omitempty"`
	CreatedDate    string         `json:"created_date,omitempty"`
	UpdatedDate    string         `json:"updated_date,omitempty"`
	ExpirationDate string         `json:"expiration_date,omitempty"`
	Registrar      *SimpleContact `json:"registrar,omitempty"`
	Registrant     *SimpleContact `json:"registrant,omitempty"`
	AdminContact   *SimpleContact `json:"admin_contact,omitempty"`
	TechContact    *SimpleContact `json:"tech_contact,omitempty"`
	Nameservers    []SimpleNS     `json:"nameservers,omitempty"`
	DNSSEC         *SimpleDNSSEC  `json:"dnssec,omitempty"`
	Country        string         `json:"country,omitempty"`
	RDAPServer     string         `json:"rdap_server,omitempty"`
	Cached         bool           `json:"cached,omitempty"`
}

// SimpleDNSSEC represents DNSSEC information.
type SimpleDNSSEC struct {
	Signed           bool `json:"signed"`
	DelegationSigned bool `json:"delegation_signed"`
}

// IPResponse represents a simplified IP lookup response.
type IPResponse struct {
	StartAddress string         `json:"start_address"`
	EndAddress   string         `json:"end_address"`
	CIDR         []string       `json:"cidr,omitempty"`
	IPVersion    string         `json:"ip_version,omitempty"`
	Handle       string         `json:"handle,omitempty"`
	Name         string         `json:"name,omitempty"`
	Type         string         `json:"type,omitempty"`
	ParentHandle string         `json:"parent_handle,omitempty"`
	Status       []string       `json:"status,omitempty"`
	Country      string         `json:"country,omitempty"`
	Registrant   *SimpleContact `json:"registrant,omitempty"`
	AdminContact *SimpleContact `json:"admin_contact,omitempty"`
	TechContact  *SimpleContact `json:"tech_contact,omitempty"`
	AbuseContact *SimpleContact `json:"abuse_contact,omitempty"`
	CreatedDate  string         `json:"created_date,omitempty"`
	UpdatedDate  string         `json:"updated_date,omitempty"`
	RDAPServer   string         `json:"rdap_server,omitempty"`
	Cached       bool           `json:"cached,omitempty"`
}

// ASNResponse represents a simplified ASN lookup response.
type ASNResponse struct {
	StartAutnum uint32         `json:"start_autnum"`
	EndAutnum   uint32         `json:"end_autnum"`
	Handle      string         `json:"handle,omitempty"`
	Name        string         `json:"name,omitempty"`
	Type        string         `json:"type,omitempty"`
	Status      []string       `json:"status,omitempty"`
	Country     string         `json:"country,omitempty"`
	CreatedDate string         `json:"created_date,omitempty"`
	UpdatedDate string         `json:"updated_date,omitempty"`
	Entities    []SimpleEntity `json:"entities,omitempty"`
	RDAPServer  string         `json:"rdap_server,omitempty"`
	Cached      bool           `json:"cached,omitempty"`
}

// EntityResponse represents a simplified entity lookup response.
type EntityResponse struct {
	Handle        string           `json:"handle"`
	Name          string           `json:"name,omitempty"`
	Organization  string           `json:"organization,omitempty"`
	Email         string           `json:"email,omitempty"`
	Phone         string           `json:"phone,omitempty"`
	Address       string           `json:"address,omitempty"`
	Country       string           `json:"country,omitempty"`
	Roles         []string         `json:"roles,omitempty"`
	Status        []string         `json:"status,omitempty"`
	CreatedDate   string           `json:"created_date,omitempty"`
	UpdatedDate   string           `json:"updated_date,omitempty"`
	RelatedIPNets []SimpleIPNet    `json:"related_ip_networks,omitempty"`
	RelatedASNs   []SimpleASNEntry `json:"related_asns,omitempty"`
	RDAPServer    string           `json:"rdap_server,omitempty"`
	Cached        bool             `json:"cached,omitempty"`
}

// SimpleContact contains simplified contact information.
type SimpleContact struct {
	Handle       string   `json:"handle,omitempty"`
	Name         string   `json:"name,omitempty"`
	Organization string   `json:"organization,omitempty"`
	Email        string   `json:"email,omitempty"`
	Phone        string   `json:"phone,omitempty"`
	Address      string   `json:"address,omitempty"`
	Country      string   `json:"country,omitempty"`
	Roles        []string `json:"roles,omitempty"`
}

// SimpleNS represents a nameserver with optional IP addresses.
type SimpleNS struct {
	Name        string   `json:"name"`
	UnicodeName string   `json:"unicode_name,omitempty"`
	IPv4        []string `json:"ipv4,omitempty"`
	IPv6        []string `json:"ipv6,omitempty"`
}

// SimpleEntity represents a simplified entity in IP/ASN responses.
type SimpleEntity struct {
	Handle       string   `json:"handle,omitempty"`
	Name         string   `json:"name,omitempty"`
	Organization string   `json:"organization,omitempty"`
	Email        string   `json:"email,omitempty"`
	Phone        string   `json:"phone,omitempty"`
	Roles        []string `json:"roles,omitempty"`
	Country      string   `json:"country,omitempty"`
}

// SimpleIPNet represents a related IP network.
type SimpleIPNet struct {
	Handle       string `json:"handle,omitempty"`
	StartAddress string `json:"start_address,omitempty"`
	EndAddress   string `json:"end_address,omitempty"`
	Name         string `json:"name,omitempty"`
	Country      string `json:"country,omitempty"`
}

// SimpleASNEntry represents a related ASN.
type SimpleASNEntry struct {
	ASN     uint32 `json:"asn,omitempty"`
	Handle  string `json:"handle,omitempty"`
	Name    string `json:"name,omitempty"`
	Country string `json:"country,omitempty"`
}

// BatchRequest represents a batch lookup request.
type BatchRequest struct {
	Queries []BatchQuery `json:"queries"`
}

// BatchQuery represents a single query in a batch request.
type BatchQuery struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	ServerURL string `json:"server_url,omitempty"` // Only for entity queries
}

// BatchResponse represents a batch lookup response.
type BatchResponse struct {
	Results []BatchResult `json:"results"`
	Stats   *BatchStats   `json:"stats,omitempty"`
}

// BatchResult represents a single result in a batch response.
type BatchResult struct {
	Type   string      `json:"type"`
	Value  string      `json:"value"`
	Data   interface{} `json:"data,omitempty"`
	Cached bool        `json:"cached,omitempty"`
	Error  string      `json:"error,omitempty"`
}

// BatchStats contains statistics about a batch request.
type BatchStats struct {
	Total      int   `json:"total"`
	Success    int   `json:"success"`
	Errors     int   `json:"errors"`
	CacheHits  int   `json:"cache_hits"`
	DurationMs int64 `json:"duration_ms"`
}

// MetaResponse represents the /meta endpoint response.
type MetaResponse struct {
	Component string `json:"component"`
	Version   string `json:"version"`
	Hostname  string `json:"hostname,omitempty"`
}

// ErrorResponse represents an error response from the API.
type ErrorResponse struct {
	Error *ErrorDetail `json:"error,omitempty"`
}

// ErrorDetail contains error details.
type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Conversion functions from internal/schema types to public types.

// domainFromSchema converts an internal SimpleDomain to a public DomainResponse.
func domainFromSchema(s *schema.SimpleDomain) *DomainResponse {
	if s == nil {
		return nil
	}
	resp := &DomainResponse{
		Name:           s.Name,
		UnicodeName:    s.UnicodeName,
		Status:         s.Status,
		CreatedDate:    s.CreatedDate,
		UpdatedDate:    s.UpdatedDate,
		ExpirationDate: s.ExpirationDate,
		Registrar:      contactFromSchema(s.Registrar),
		Registrant:     contactFromSchema(s.Registrant),
		AdminContact:   contactFromSchema(s.AdminContact),
		TechContact:    contactFromSchema(s.TechContact),
		RDAPServer:     s.RDAPServer,
	}

	// Convert nameservers
	if len(s.Nameservers) > 0 {
		resp.Nameservers = make([]SimpleNS, len(s.Nameservers))
		for i, ns := range s.Nameservers {
			resp.Nameservers[i] = SimpleNS{
				Name:        ns.Name,
				UnicodeName: ns.UnicodeName,
				IPv4:        ns.IPv4,
				IPv6:        ns.IPv6,
			}
		}
	}

	// Convert DNSSEC
	if s.DNSSEC != nil {
		resp.DNSSEC = &SimpleDNSSEC{
			Signed:           s.DNSSEC.Signed,
			DelegationSigned: s.DNSSEC.DelegationSigned,
		}
	}

	// Extract country from registrant if available
	if s.Registrant != nil && s.Registrant.Country != "" {
		resp.Country = s.Registrant.Country
	}

	return resp
}

// ipFromSchema converts an internal SimpleIP to a public IPResponse.
func ipFromSchema(s *schema.SimpleIP) *IPResponse {
	if s == nil {
		return nil
	}
	return &IPResponse{
		StartAddress: s.StartAddress,
		EndAddress:   s.EndAddress,
		CIDR:         s.CIDR,
		IPVersion:    s.IPVersion,
		Handle:       s.Handle,
		Name:         s.Name,
		Type:         s.Type,
		ParentHandle: s.ParentHandle,
		Status:       s.Status,
		Country:      s.Country,
		Registrant:   contactFromSchema(s.Registrant),
		AdminContact: contactFromSchema(s.AdminContact),
		TechContact:  contactFromSchema(s.TechContact),
		AbuseContact: contactFromSchema(s.AbuseContact),
		CreatedDate:  s.CreatedDate,
		UpdatedDate:  s.UpdatedDate,
		RDAPServer:   s.RDAPServer,
	}
}

// asnFromSchema converts an internal SimpleASN to a public ASNResponse.
func asnFromSchema(s *schema.SimpleASN) *ASNResponse {
	if s == nil {
		return nil
	}
	resp := &ASNResponse{
		StartAutnum: s.ASN, // Use ASN as StartAutnum for compatibility
		EndAutnum:   s.ASN,
		Handle:      s.Handle,
		Name:        s.Name,
		Type:        s.Type,
		Status:      s.Status,
		Country:     s.Country,
		CreatedDate: s.CreatedDate,
		UpdatedDate: s.UpdatedDate,
		RDAPServer:  s.RDAPServer,
	}

	// Use range if different from single ASN
	if s.StartASN != 0 {
		resp.StartAutnum = s.StartASN
	}
	if s.EndASN != 0 {
		resp.EndAutnum = s.EndASN
	}

	// Convert entities from contacts
	entities := make([]SimpleEntity, 0, 4)
	if s.Registrant != nil {
		entities = append(entities, entityFromContact(s.Registrant, "registrant"))
	}
	if s.AdminContact != nil {
		entities = append(entities, entityFromContact(s.AdminContact, "administrative"))
	}
	if s.TechContact != nil {
		entities = append(entities, entityFromContact(s.TechContact, "technical"))
	}
	if s.AbuseContact != nil {
		entities = append(entities, entityFromContact(s.AbuseContact, "abuse"))
	}
	if len(entities) > 0 {
		resp.Entities = entities
	}

	return resp
}

// entityFromSchema converts an internal SimpleEntityFull to a public EntityResponse.
func entityFromSchema(s *schema.SimpleEntityFull) *EntityResponse {
	if s == nil {
		return nil
	}
	resp := &EntityResponse{
		Handle:       s.Handle,
		Name:         s.Name,
		Organization: s.Organization,
		Email:        s.Email,
		Phone:        s.Phone,
		Address:      s.Address,
		Country:      s.Country,
		Roles:        s.Roles,
		Status:       s.Status,
		CreatedDate:  s.CreatedDate,
		UpdatedDate:  s.UpdatedDate,
		RDAPServer:   s.RDAPServer,
	}

	// Convert related IP networks
	if len(s.RelatedIPNets) > 0 {
		resp.RelatedIPNets = make([]SimpleIPNet, len(s.RelatedIPNets))
		for i, net := range s.RelatedIPNets {
			resp.RelatedIPNets[i] = SimpleIPNet{
				Handle:       net.Handle,
				StartAddress: net.StartAddress,
				EndAddress:   net.EndAddress,
				Name:         net.Name,
				Country:      net.Country,
			}
		}
	}

	// Convert related ASNs
	if len(s.RelatedASNs) > 0 {
		resp.RelatedASNs = make([]SimpleASNEntry, len(s.RelatedASNs))
		for i, asn := range s.RelatedASNs {
			resp.RelatedASNs[i] = SimpleASNEntry{
				ASN:     asn.ASN,
				Handle:  asn.Handle,
				Name:    asn.Name,
				Country: asn.Country,
			}
		}
	}

	return resp
}

// contactFromSchema converts an internal SimpleEntity to a public SimpleContact.
func contactFromSchema(s *schema.SimpleEntity) *SimpleContact {
	if s == nil {
		return nil
	}
	return &SimpleContact{
		Handle:       s.Handle,
		Name:         s.Name,
		Organization: s.Organization,
		Email:        s.Email,
		Phone:        s.Phone,
		Address:      s.Address,
		Country:      s.Country,
		Roles:        s.Roles,
	}
}

// entityFromContact converts a SimpleEntity (contact) to a SimpleEntity for ASN response.
func entityFromContact(s *schema.SimpleEntity, role string) SimpleEntity {
	e := SimpleEntity{
		Handle:       s.Handle,
		Name:         s.Name,
		Organization: s.Organization,
		Email:        s.Email,
		Phone:        s.Phone,
		Country:      s.Country,
	}
	if len(s.Roles) > 0 {
		e.Roles = s.Roles
	} else {
		e.Roles = []string{role}
	}
	return e
}
