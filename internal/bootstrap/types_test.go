package bootstrap

import (
	"testing"
	"time"
)

func TestNewBootstrap(t *testing.T) {
	b := NewBootstrap()

	if b.DNS == nil {
		t.Error("DNS bootstrap is nil")
	}
	if b.IPv4 == nil {
		t.Error("IPv4 bootstrap is nil")
	}
	if b.IPv6 == nil {
		t.Error("IPv6 bootstrap is nil")
	}
	if b.ASN == nil {
		t.Error("ASN bootstrap is nil")
	}

	// Check initial counts
	if b.DNS.TLDCount() != 0 {
		t.Errorf("initial TLD count = %d, want 0", b.DNS.TLDCount())
	}
	if b.IPv4.PrefixCount() != 0 {
		t.Errorf("initial IPv4 prefix count = %d, want 0", b.IPv4.PrefixCount())
	}
	if b.IPv6.PrefixCount() != 0 {
		t.Errorf("initial IPv6 prefix count = %d, want 0", b.IPv6.PrefixCount())
	}
	if b.ASN.RangeCount() != 0 {
		t.Errorf("initial ASN range count = %d, want 0", b.ASN.RangeCount())
	}
}

func TestDNSBootstrap_LastRefresh(t *testing.T) {
	dns := &DNSBootstrap{
		tldToURLs: make(map[string][]string),
	}

	// Initial should be zero
	if !dns.LastRefresh().IsZero() {
		t.Error("initial LastRefresh should be zero")
	}

	// Set a time
	now := time.Now()
	dns.mu.Lock()
	dns.lastRefresh = now
	dns.mu.Unlock()

	if !dns.LastRefresh().Equal(now) {
		t.Errorf("LastRefresh = %v, want %v", dns.LastRefresh(), now)
	}
}

func TestIPv4Bootstrap_LastRefresh(t *testing.T) {
	ipv4 := &IPv4Bootstrap{
		prefixes: make([]ipv4Entry, 0),
	}

	if !ipv4.LastRefresh().IsZero() {
		t.Error("initial LastRefresh should be zero")
	}
}

func TestIPv6Bootstrap_LastRefresh(t *testing.T) {
	ipv6 := &IPv6Bootstrap{
		prefixes: make([]ipv6Entry, 0),
	}

	if !ipv6.LastRefresh().IsZero() {
		t.Error("initial LastRefresh should be zero")
	}
}

func TestASNBootstrap_LastRefresh(t *testing.T) {
	asn := &ASNBootstrap{
		ranges: make([]asnEntry, 0),
	}

	if !asn.LastRefresh().IsZero() {
		t.Error("initial LastRefresh should be zero")
	}
}
