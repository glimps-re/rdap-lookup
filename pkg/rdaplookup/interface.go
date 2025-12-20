// Package rdaplookup provides client libraries for RDAP (Registration Data Access Protocol) lookups.
package rdaplookup

import "context"

// RDAPClient defines the common interface for RDAP lookups.
// Both Client (REST API) and StandaloneClient implement this interface,
// allowing them to be used interchangeably.
//
// Example usage with interface for flexibility:
//
//	var client rdaplookup.RDAPClient
//	if serverURL != "" {
//	    client, _ = rdaplookup.NewClient(serverURL)
//	} else {
//	    client, _ = rdaplookup.NewStandaloneClient()
//	}
//	defer client.Close()
//	resp, _ := client.LookupDomain(ctx, "example.com")
type RDAPClient interface {
	// LookupDomain performs a domain lookup.
	// If domain normalization is enabled (default), subdomains are automatically
	// reduced to the registrable domain (e.g., "www.example.com" -> "example.com").
	LookupDomain(ctx context.Context, name string) (*DomainResponse, error)

	// LookupIP performs an IP address lookup (IPv4 or IPv6).
	LookupIP(ctx context.Context, addr string) (*IPResponse, error)

	// LookupASN performs an ASN lookup.
	// The asn parameter can be a number (15169) or prefixed (AS15169).
	LookupASN(ctx context.Context, asn string) (*ASNResponse, error)

	// LookupEntity performs an entity lookup by handle.
	// Requires the RDAP server URL where the entity is registered.
	LookupEntity(ctx context.Context, handle, serverURL string) (*EntityResponse, error)

	// BatchLookup performs a batch lookup of multiple queries.
	BatchLookup(ctx context.Context, req *BatchRequest) (*BatchResponse, error)

	// Close releases resources. Safe to call multiple times.
	// For the REST API Client, this is a no-op.
	// For StandaloneClient, this stops background goroutines and releases cache.
	Close() error
}

// Compile-time interface compliance check for Client.
var _ RDAPClient = (*Client)(nil)
