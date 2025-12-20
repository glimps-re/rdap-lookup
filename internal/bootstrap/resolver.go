package bootstrap

import (
	"errors"
	"net"
	"net/netip"
	"sort"
	"strings"
)

// Common errors returned by resolvers.
var (
	ErrNotFound       = errors.New("no RDAP server found")
	ErrInvalidInput   = errors.New("invalid input")
	ErrNotInitialized = errors.New("bootstrap data not initialized")
)

// ResolveDomain returns the RDAP URLs for the given domain name.
// The domain should be a fully qualified domain name (e.g., "example.com").
// Returns the URLs for the TLD of the domain.
func (d *DNSBootstrap) ResolveDomain(domain string) ([]string, error) {
	if domain == "" {
		return nil, ErrInvalidInput
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	if len(d.tldToURLs) == 0 {
		return nil, ErrNotInitialized
	}

	// Extract TLD from domain (last label)
	tld := extractTLD(domain)
	if tld == "" {
		return nil, ErrInvalidInput
	}

	// Look up TLD in lowercase
	urls, ok := d.tldToURLs[strings.ToLower(tld)]
	if !ok {
		return nil, ErrNotFound
	}

	return urls, nil
}

// ResolveTLD returns the RDAP URLs for the given TLD directly.
func (d *DNSBootstrap) ResolveTLD(tld string) ([]string, error) {
	if tld == "" {
		return nil, ErrInvalidInput
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	if len(d.tldToURLs) == 0 {
		return nil, ErrNotInitialized
	}

	// Remove leading dot if present
	tld = strings.TrimPrefix(tld, ".")

	urls, ok := d.tldToURLs[strings.ToLower(tld)]
	if !ok {
		return nil, ErrNotFound
	}

	return urls, nil
}

// ResolveIP returns the RDAP URLs for the given IPv4 address.
// Uses cidranger radix tree for O(log n) prefix matching.
func (i *IPv4Bootstrap) ResolveIP(addr netip.Addr) ([]string, error) {
	if !addr.IsValid() || !addr.Is4() {
		return nil, ErrInvalidInput
	}

	i.mu.RLock()
	defer i.mu.RUnlock()

	if i.ranger == nil || len(i.prefixes) == 0 {
		return nil, ErrNotInitialized
	}

	// Use cidranger for O(log n) lookup
	ip := net.IP(addr.AsSlice())
	entries, err := i.ranger.ContainingNetworks(ip)
	if err != nil || len(entries) == 0 {
		return nil, ErrNotFound
	}

	// Find most specific (longest prefix match)
	var best *ipv4RangerEntry
	var bestBits int
	for _, e := range entries {
		entry := e.(*ipv4RangerEntry)
		ones, _ := entry.network.Mask.Size()
		if best == nil || ones > bestBits {
			best = entry
			bestBits = ones
		}
	}

	if best == nil {
		return nil, ErrNotFound
	}

	return best.urls, nil
}

// ResolveIPString parses and resolves an IPv4 address string.
func (i *IPv4Bootstrap) ResolveIPString(addrStr string) ([]string, error) {
	addr, err := netip.ParseAddr(addrStr)
	if err != nil {
		return nil, ErrInvalidInput
	}
	return i.ResolveIP(addr)
}

// ResolveIP returns the RDAP URLs for the given IPv6 address.
// Uses cidranger radix tree for O(log n) prefix matching.
func (i *IPv6Bootstrap) ResolveIP(addr netip.Addr) ([]string, error) {
	if !addr.IsValid() || !addr.Is6() {
		return nil, ErrInvalidInput
	}

	i.mu.RLock()
	defer i.mu.RUnlock()

	if i.ranger == nil || len(i.prefixes) == 0 {
		return nil, ErrNotInitialized
	}

	// Use cidranger for O(log n) lookup
	ip := net.IP(addr.AsSlice())
	entries, err := i.ranger.ContainingNetworks(ip)
	if err != nil || len(entries) == 0 {
		return nil, ErrNotFound
	}

	// Find most specific (longest prefix match)
	var best *ipv6RangerEntry
	var bestBits int
	for _, e := range entries {
		entry := e.(*ipv6RangerEntry)
		ones, _ := entry.network.Mask.Size()
		if best == nil || ones > bestBits {
			best = entry
			bestBits = ones
		}
	}

	if best == nil {
		return nil, ErrNotFound
	}

	return best.urls, nil
}

// ResolveIPString parses and resolves an IPv6 address string.
func (i *IPv6Bootstrap) ResolveIPString(addrStr string) ([]string, error) {
	addr, err := netip.ParseAddr(addrStr)
	if err != nil {
		return nil, ErrInvalidInput
	}
	return i.ResolveIP(addr)
}

// ResolveASN returns the RDAP URLs for the given ASN.
// Uses binary search for O(log n) lookup when ranges are sorted by start.
func (a *ASNBootstrap) ResolveASN(asn uint32) ([]string, error) {
	if asn == 0 {
		return nil, ErrInvalidInput
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	if len(a.ranges) == 0 {
		return nil, ErrNotInitialized
	}

	// Binary search to find the first range where start > asn
	idx := sort.Search(len(a.ranges), func(i int) bool {
		return a.ranges[i].start > asn
	})

	// Check ranges that could contain asn (from idx-1 backwards)
	for i := idx - 1; i >= 0; i-- {
		if a.ranges[i].start <= asn && asn <= a.ranges[i].end {
			return a.ranges[i].urls, nil
		}
		// Early termination: if end is less than asn, no earlier ranges can contain it
		if a.ranges[i].end < asn {
			break
		}
	}

	return nil, ErrNotFound
}

// extractTLD extracts the TLD from a domain name.
// For "example.com" returns "com".
// For "sub.example.co.uk" returns "uk" (not handling multi-level TLDs).
func extractTLD(domain string) string {
	// Remove trailing dot if present
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return ""
	}

	// Find the last label
	lastDot := strings.LastIndex(domain, ".")
	if lastDot == -1 {
		// No dot, the whole thing is the TLD (e.g., "com")
		return domain
	}

	return domain[lastDot+1:]
}

// Resolver provides a unified interface for resolving RDAP URLs.
type Resolver struct {
	bootstrap *Bootstrap
}

// NewResolver creates a new resolver with the given bootstrap data.
func NewResolver(bootstrap *Bootstrap) *Resolver {
	return &Resolver{bootstrap: bootstrap}
}

// ResolveDomain returns the RDAP URLs for the given domain.
func (r *Resolver) ResolveDomain(domain string) ([]string, error) {
	return r.bootstrap.DNS.ResolveDomain(domain)
}

// ResolveIP returns the RDAP URLs for the given IP address (v4 or v6).
func (r *Resolver) ResolveIP(addrStr string) ([]string, error) {
	addr, err := netip.ParseAddr(addrStr)
	if err != nil {
		return nil, ErrInvalidInput
	}

	if addr.Is4() {
		return r.bootstrap.IPv4.ResolveIP(addr)
	}
	return r.bootstrap.IPv6.ResolveIP(addr)
}

// ResolveASN returns the RDAP URLs for the given ASN.
func (r *Resolver) ResolveASN(asn uint32) ([]string, error) {
	return r.bootstrap.ASN.ResolveASN(asn)
}

// Bootstrap returns the underlying bootstrap data.
func (r *Resolver) Bootstrap() *Bootstrap {
	return r.bootstrap
}

// GetAllRDAPServers returns all unique RDAP server URLs from the bootstrap data.
// This includes servers from DNS, IPv4, IPv6, and ASN bootstrap files.
func (r *Resolver) GetAllRDAPServers() []string {
	servers := make(map[string]struct{})

	// Collect DNS servers
	r.bootstrap.DNS.mu.RLock()
	for _, urls := range r.bootstrap.DNS.tldToURLs {
		for _, u := range urls {
			servers[u] = struct{}{}
		}
	}
	r.bootstrap.DNS.mu.RUnlock()

	// Collect IPv4 servers
	r.bootstrap.IPv4.mu.RLock()
	for _, entry := range r.bootstrap.IPv4.prefixes {
		for _, u := range entry.urls {
			servers[u] = struct{}{}
		}
	}
	r.bootstrap.IPv4.mu.RUnlock()

	// Collect IPv6 servers
	r.bootstrap.IPv6.mu.RLock()
	for _, entry := range r.bootstrap.IPv6.prefixes {
		for _, u := range entry.urls {
			servers[u] = struct{}{}
		}
	}
	r.bootstrap.IPv6.mu.RUnlock()

	// Collect ASN servers
	r.bootstrap.ASN.mu.RLock()
	for _, entry := range r.bootstrap.ASN.ranges {
		for _, u := range entry.urls {
			servers[u] = struct{}{}
		}
	}
	r.bootstrap.ASN.mu.RUnlock()

	// Convert to slice
	result := make([]string, 0, len(servers))
	for u := range servers {
		result = append(result, u)
	}

	return result
}
