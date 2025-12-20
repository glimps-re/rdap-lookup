package rdaplookup

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
