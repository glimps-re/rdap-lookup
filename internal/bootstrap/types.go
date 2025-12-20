// Package bootstrap provides IANA RDAP bootstrap data management.
// It fetches and parses IANA bootstrap files to resolve domain TLDs,
// IP addresses, and ASNs to their respective RDAP servers.
package bootstrap

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/yl2chen/cidranger"
)

// IANABootstrapFile represents the structure of IANA bootstrap JSON files.
// See https://data.iana.org/rdap/
type IANABootstrapFile struct {
	Description string  `json:"description"`
	Publication string  `json:"publication"`
	Version     string  `json:"version"`
	Services    [][]any `json:"services"`
}

// ServiceEntry represents a parsed service entry from the bootstrap file.
// Each entry maps a set of keys (TLDs, IP ranges, or ASN ranges) to RDAP URLs.
type ServiceEntry struct {
	Keys []string
	URLs []string
}

// DNSBootstrap holds the parsed DNS/domain bootstrap data.
type DNSBootstrap struct {
	mu          sync.RWMutex
	tldToURLs   map[string][]string // lowercase TLD -> RDAP URLs
	lastRefresh time.Time
	publication string
	version     string
}

// IPv4Bootstrap holds the parsed IPv4 bootstrap data.
type IPv4Bootstrap struct {
	mu          sync.RWMutex
	ranger      cidranger.Ranger // Radix tree for O(log n) prefix lookup
	prefixes    []ipv4Entry      // Keep for iteration in GetAllRDAPServers
	lastRefresh time.Time
	publication string
	version     string
}

// ipv4Entry represents a single IPv4 prefix to RDAP URL mapping.
type ipv4Entry struct {
	prefix netip.Prefix
	urls   []string
}

// ipv4RangerEntry implements cidranger.RangerEntry for IPv4 prefix lookup.
type ipv4RangerEntry struct {
	network net.IPNet
	urls    []string
}

// Network returns the network for the cidranger interface.
func (e *ipv4RangerEntry) Network() net.IPNet {
	return e.network
}

// IPv6Bootstrap holds the parsed IPv6 bootstrap data.
type IPv6Bootstrap struct {
	mu          sync.RWMutex
	ranger      cidranger.Ranger // Radix tree for O(log n) prefix lookup
	prefixes    []ipv6Entry      // Keep for iteration in GetAllRDAPServers
	lastRefresh time.Time
	publication string
	version     string
}

// ipv6Entry represents a single IPv6 prefix to RDAP URL mapping.
type ipv6Entry struct {
	prefix netip.Prefix
	urls   []string
}

// ipv6RangerEntry implements cidranger.RangerEntry for IPv6 prefix lookup.
type ipv6RangerEntry struct {
	network net.IPNet
	urls    []string
}

// Network returns the network for the cidranger interface.
func (e *ipv6RangerEntry) Network() net.IPNet {
	return e.network
}

// ASNBootstrap holds the parsed ASN bootstrap data.
type ASNBootstrap struct {
	mu          sync.RWMutex
	ranges      []asnEntry
	lastRefresh time.Time
	publication string
	version     string
}

// asnEntry represents a single ASN range to RDAP URL mapping.
type asnEntry struct {
	start uint32
	end   uint32
	urls  []string
}

// Bootstrap holds all bootstrap data for RDAP server discovery.
type Bootstrap struct {
	DNS  *DNSBootstrap
	IPv4 *IPv4Bootstrap
	IPv6 *IPv6Bootstrap
	ASN  *ASNBootstrap
}

// NewBootstrap creates a new empty Bootstrap instance.
func NewBootstrap() *Bootstrap {
	return &Bootstrap{
		DNS: &DNSBootstrap{
			tldToURLs: make(map[string][]string),
		},
		IPv4: &IPv4Bootstrap{
			ranger:   cidranger.NewPCTrieRanger(),
			prefixes: make([]ipv4Entry, 0),
		},
		IPv6: &IPv6Bootstrap{
			ranger:   cidranger.NewPCTrieRanger(),
			prefixes: make([]ipv6Entry, 0),
		},
		ASN: &ASNBootstrap{
			ranges: make([]asnEntry, 0),
		},
	}
}

// LastRefresh returns the time of the last successful DNS bootstrap refresh.
func (d *DNSBootstrap) LastRefresh() time.Time {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.lastRefresh
}

// TLDCount returns the number of TLDs in the bootstrap data.
func (d *DNSBootstrap) TLDCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.tldToURLs)
}

// LastRefresh returns the time of the last successful IPv4 bootstrap refresh.
func (i *IPv4Bootstrap) LastRefresh() time.Time {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.lastRefresh
}

// PrefixCount returns the number of IPv4 prefixes in the bootstrap data.
func (i *IPv4Bootstrap) PrefixCount() int {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return len(i.prefixes)
}

// LastRefresh returns the time of the last successful IPv6 bootstrap refresh.
func (i *IPv6Bootstrap) LastRefresh() time.Time {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.lastRefresh
}

// PrefixCount returns the number of IPv6 prefixes in the bootstrap data.
func (i *IPv6Bootstrap) PrefixCount() int {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return len(i.prefixes)
}

// LastRefresh returns the time of the last successful ASN bootstrap refresh.
func (a *ASNBootstrap) LastRefresh() time.Time {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.lastRefresh
}

// RangeCount returns the number of ASN ranges in the bootstrap data.
func (a *ASNBootstrap) RangeCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.ranges)
}

// SetTLDURLs sets the RDAP URLs for a TLD. Used primarily for testing.
func (d *DNSBootstrap) SetTLDURLs(tld string, urls []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.tldToURLs[tld] = urls
}

// AddPrefix adds an IPv4 prefix mapping. Used primarily for testing.
func (i *IPv4Bootstrap) AddPrefix(cidr string, urls []string) error {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return err
	}

	// Convert netip.Prefix to net.IPNet for cidranger
	ipNet := prefixToIPNet(prefix)

	i.mu.Lock()
	defer i.mu.Unlock()

	// Add to ranger for fast lookup
	if i.ranger == nil {
		i.ranger = cidranger.NewPCTrieRanger()
	}
	if err := i.ranger.Insert(&ipv4RangerEntry{network: ipNet, urls: urls}); err != nil {
		return err
	}

	// Also keep in slice for iteration
	i.prefixes = append(i.prefixes, ipv4Entry{prefix: prefix, urls: urls})
	return nil
}

// AddPrefix adds an IPv6 prefix mapping. Used primarily for testing.
func (i *IPv6Bootstrap) AddPrefix(cidr string, urls []string) error {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return err
	}

	// Convert netip.Prefix to net.IPNet for cidranger
	ipNet := prefixToIPNet(prefix)

	i.mu.Lock()
	defer i.mu.Unlock()

	// Add to ranger for fast lookup
	if i.ranger == nil {
		i.ranger = cidranger.NewPCTrieRanger()
	}
	if err := i.ranger.Insert(&ipv6RangerEntry{network: ipNet, urls: urls}); err != nil {
		return err
	}

	// Also keep in slice for iteration
	i.prefixes = append(i.prefixes, ipv6Entry{prefix: prefix, urls: urls})
	return nil
}

// prefixToIPNet converts a netip.Prefix to a net.IPNet for cidranger compatibility.
func prefixToIPNet(prefix netip.Prefix) net.IPNet {
	addr := prefix.Addr()
	bits := prefix.Bits()

	var ip net.IP
	var mask net.IPMask

	if addr.Is4() {
		ip = net.IP(addr.AsSlice())
		mask = net.CIDRMask(bits, 32)
	} else {
		ip = net.IP(addr.AsSlice())
		mask = net.CIDRMask(bits, 128)
	}

	return net.IPNet{IP: ip, Mask: mask}
}

// AddRange adds an ASN range mapping. Used primarily for testing.
func (a *ASNBootstrap) AddRange(start, end uint32, urls []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ranges = append(a.ranges, asnEntry{start: start, end: end, urls: urls})
}
