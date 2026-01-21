// Package whois provides WHOIS protocol client and parsing functionality
// for domain registration data lookup when RDAP is not available.
package whois

import "time"

// ParsedDomain represents domain registration data extracted from a WHOIS response.
// This is the intermediate representation before transformation to SimpleDomain.
type ParsedDomain struct {
	// DomainName is the fully qualified domain name.
	DomainName string
	// UnicodeName is the internationalized domain name (IDN) if applicable.
	UnicodeName string
	// RegistryDomainID is the registry's unique identifier for this domain.
	RegistryDomainID string
	// Status contains the domain status flags.
	Status []string
	// Nameservers contains the domain's nameserver hostnames.
	Nameservers []string

	// CreatedDate is when the domain was first registered.
	CreatedDate *time.Time
	// UpdatedDate is when the domain was last modified.
	UpdatedDate *time.Time
	// ExpirationDate is when the domain registration expires.
	ExpirationDate *time.Time

	// Registrar holds registrar information.
	Registrar *ParsedEntity
	// Registrant holds registrant contact information.
	Registrant *ParsedEntity
	// AdminContact holds administrative contact information.
	AdminContact *ParsedEntity
	// TechContact holds technical contact information.
	TechContact *ParsedEntity

	// DNSSECSigned indicates whether the domain is DNSSEC signed.
	DNSSECSigned *bool

	// WHOISServer is the WHOIS server that provided this data.
	WHOISServer string
	// RawResponse is the original WHOIS response text.
	RawResponse string
}

// ParsedEntity represents a contact or organization from WHOIS data.
type ParsedEntity struct {
	// Handle is the registry identifier for this entity.
	Handle string
	// Name is the entity's name.
	Name string
	// Organization is the entity's organization name.
	Organization string
	// Email is the entity's email address.
	Email string
	// Phone is the entity's phone number.
	Phone string
	// Fax is the entity's fax number.
	Fax string
	// Address is the entity's formatted address.
	Address string
	// Country is the ISO country code.
	Country string
	// Street is the street address component.
	Street string
	// City is the city component.
	City string
	// State is the state/province component.
	State string
	// PostalCode is the postal/ZIP code component.
	PostalCode string
}

// Confidence indicates the reliability of parsed WHOIS data.
type Confidence string

const (
	// ConfidenceHigh indicates data was parsed by a TLD-specific parser.
	ConfidenceHigh Confidence = "high"
	// ConfidenceLow indicates data was parsed by the generic best-effort parser.
	ConfidenceLow Confidence = "low"
)

// ParseResult contains the result of parsing a WHOIS response.
type ParseResult struct {
	// Domain contains the parsed domain data.
	Domain *ParsedDomain
	// Confidence indicates the reliability of the parsed data.
	Confidence Confidence
	// ParserName identifies which parser was used.
	ParserName string
	// Errors contains any non-fatal parsing errors encountered.
	Errors []string
}

// QueryResult contains the result of a WHOIS query.
type QueryResult struct {
	// Server is the WHOIS server that was queried.
	Server string
	// Response is the raw WHOIS response text.
	Response string
	// Duration is how long the query took.
	Duration time.Duration
	// Cached indicates whether this result came from cache.
	Cached bool
}

// DataSource indicates the source of domain registration data.
type DataSource string

const (
	// DataSourceRDAP indicates data came from an RDAP server.
	DataSourceRDAP DataSource = "rdap"
	// DataSourceWHOIS indicates data came from a WHOIS server.
	DataSourceWHOIS DataSource = "whois"
)

// WHOISError represents a WHOIS-specific error.
type WHOISError struct {
	// Op is the operation that failed.
	Op string
	// Server is the WHOIS server involved.
	Server string
	// Err is the underlying error.
	Err error
}

// Error implements the error interface.
func (e *WHOISError) Error() string {
	if e.Server != "" {
		return e.Op + " " + e.Server + ": " + e.Err.Error()
	}
	return e.Op + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *WHOISError) Unwrap() error {
	return e.Err
}
