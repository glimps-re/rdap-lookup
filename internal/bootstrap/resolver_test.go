package bootstrap

import (
	"errors"
	"net/netip"
	"testing"
)

func createTestDNSBootstrap() *DNSBootstrap {
	return &DNSBootstrap{
		tldToURLs: map[string][]string{
			"com":   {"https://rdap.verisign.com/com/v1/"},
			"net":   {"https://rdap.verisign.com/net/v1/"},
			"org":   {"https://rdap.publicinterestregistry.org/rdap/"},
			"co.uk": {"https://rdap.nominet.uk/uk/"},
		},
	}
}

func createTestIPv4Bootstrap() *IPv4Bootstrap {
	ipv4 := &IPv4Bootstrap{
		prefixes: []ipv4Entry{},
	}

	// Use AddPrefix to populate both slice and ranger
	prefixes := []struct {
		cidr string
		urls []string
	}{
		{"8.0.0.0/8", []string{"https://rdap.arin.net/registry/"}},
		{"8.8.0.0/16", []string{"https://rdap.arin.net/registry/specific/"}},
		{"193.0.0.0/8", []string{"https://rdap.db.ripe.net/"}},
	}

	for _, p := range prefixes {
		_ = ipv4.AddPrefix(p.cidr, p.urls)
	}

	return ipv4
}

func createTestIPv6Bootstrap() *IPv6Bootstrap {
	ipv6 := &IPv6Bootstrap{
		prefixes: []ipv6Entry{},
	}

	// Use AddPrefix to populate both slice and ranger
	prefixes := []struct {
		cidr string
		urls []string
	}{
		{"2001::/16", []string{"https://rdap.arin.net/registry/"}},
		{"2a00::/12", []string{"https://rdap.db.ripe.net/"}},
	}

	for _, p := range prefixes {
		_ = ipv6.AddPrefix(p.cidr, p.urls)
	}

	return ipv6
}

func createTestASNBootstrap() *ASNBootstrap {
	asn := &ASNBootstrap{
		ranges: []asnEntry{},
	}

	// Use AddRange to add entries (they're already sorted by start)
	ranges := []struct {
		start, end uint32
		urls       []string
	}{
		{1, 1876, []string{"https://rdap.arin.net/registry/"}},
		{15169, 15169, []string{"https://rdap.arin.net/registry/"}},
		{28000, 29695, []string{"https://rdap.db.ripe.net/"}},
	}

	for _, r := range ranges {
		asn.AddRange(r.start, r.end, r.urls)
	}

	return asn
}

func TestDNSBootstrap_ResolveDomain(t *testing.T) {
	dns := createTestDNSBootstrap()

	tests := []struct {
		name    string
		domain  string
		wantURL string
		wantErr error
	}{
		{
			name:    "simple domain",
			domain:  "example.com",
			wantURL: "https://rdap.verisign.com/com/v1/",
		},
		{
			name:    "subdomain",
			domain:  "www.example.net",
			wantURL: "https://rdap.verisign.com/net/v1/",
		},
		{
			name:    "uppercase domain",
			domain:  "EXAMPLE.COM",
			wantURL: "https://rdap.verisign.com/com/v1/",
		},
		{
			name:    "org domain",
			domain:  "test.org",
			wantURL: "https://rdap.publicinterestregistry.org/rdap/",
		},
		{
			name:    "trailing dot",
			domain:  "example.com.",
			wantURL: "https://rdap.verisign.com/com/v1/",
		},
		{
			name:    "unknown TLD",
			domain:  "example.xyz",
			wantErr: ErrNotFound,
		},
		{
			name:    "empty domain",
			domain:  "",
			wantErr: ErrInvalidInput,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			urls, err := dns.ResolveDomain(tt.domain)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("error = %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(urls) == 0 || urls[0] != tt.wantURL {
				t.Errorf("URL = %v, want %s", urls, tt.wantURL)
			}
		})
	}
}

func TestDNSBootstrap_ResolveTLD(t *testing.T) {
	dns := createTestDNSBootstrap()

	tests := []struct {
		name    string
		tld     string
		wantURL string
		wantErr error
	}{
		{
			name:    "com",
			tld:     "com",
			wantURL: "https://rdap.verisign.com/com/v1/",
		},
		{
			name:    "with leading dot",
			tld:     ".com",
			wantURL: "https://rdap.verisign.com/com/v1/",
		},
		{
			name:    "uppercase",
			tld:     "COM",
			wantURL: "https://rdap.verisign.com/com/v1/",
		},
		{
			name:    "unknown",
			tld:     "xyz",
			wantErr: ErrNotFound,
		},
		{
			name:    "empty",
			tld:     "",
			wantErr: ErrInvalidInput,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			urls, err := dns.ResolveTLD(tt.tld)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("error = %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(urls) == 0 || urls[0] != tt.wantURL {
				t.Errorf("URL = %v, want %s", urls, tt.wantURL)
			}
		})
	}
}

func TestDNSBootstrap_NotInitialized(t *testing.T) {
	dns := &DNSBootstrap{
		tldToURLs: make(map[string][]string),
	}

	_, err := dns.ResolveDomain("example.com")
	if !errors.Is(err, ErrNotInitialized) {
		t.Errorf("error = %v, want %v", err, ErrNotInitialized)
	}
}

func TestIPv4Bootstrap_ResolveIP(t *testing.T) {
	ipv4 := createTestIPv4Bootstrap()

	tests := []struct {
		name    string
		addr    string
		wantURL string
		wantErr error
	}{
		{
			name:    "8.8.8.8 (more specific match)",
			addr:    "8.8.8.8",
			wantURL: "https://rdap.arin.net/registry/specific/",
		},
		{
			name:    "8.1.1.1 (less specific match)",
			addr:    "8.1.1.1",
			wantURL: "https://rdap.arin.net/registry/",
		},
		{
			name:    "193.0.14.129 (RIPE)",
			addr:    "193.0.14.129",
			wantURL: "https://rdap.db.ripe.net/",
		},
		{
			name:    "unknown IP",
			addr:    "192.168.1.1",
			wantErr: ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := netip.MustParseAddr(tt.addr)
			urls, err := ipv4.ResolveIP(addr)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("error = %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(urls) == 0 || urls[0] != tt.wantURL {
				t.Errorf("URL = %v, want %s", urls, tt.wantURL)
			}
		})
	}
}

func TestIPv4Bootstrap_ResolveIPString(t *testing.T) {
	ipv4 := createTestIPv4Bootstrap()

	urls, err := ipv4.ResolveIPString("8.8.8.8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(urls) == 0 {
		t.Error("expected URLs")
	}

	_, err = ipv4.ResolveIPString("invalid")
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("error = %v, want %v", err, ErrInvalidInput)
	}
}

func TestIPv4Bootstrap_InvalidInput(t *testing.T) {
	ipv4 := createTestIPv4Bootstrap()

	// IPv6 address should fail
	addr := netip.MustParseAddr("2001:db8::1")
	_, err := ipv4.ResolveIP(addr)
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("error = %v, want %v", err, ErrInvalidInput)
	}
}

func TestIPv6Bootstrap_ResolveIP(t *testing.T) {
	ipv6 := createTestIPv6Bootstrap()

	tests := []struct {
		name    string
		addr    string
		wantURL string
		wantErr error
	}{
		{
			name:    "2001:db8::1",
			addr:    "2001:db8::1",
			wantURL: "https://rdap.arin.net/registry/",
		},
		{
			name:    "2a00::1 (RIPE)",
			addr:    "2a00::1",
			wantURL: "https://rdap.db.ripe.net/",
		},
		{
			name:    "unknown IPv6",
			addr:    "3000::1",
			wantErr: ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := netip.MustParseAddr(tt.addr)
			urls, err := ipv6.ResolveIP(addr)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("error = %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(urls) == 0 || urls[0] != tt.wantURL {
				t.Errorf("URL = %v, want %s", urls, tt.wantURL)
			}
		})
	}
}

func TestIPv6Bootstrap_InvalidInput(t *testing.T) {
	ipv6 := createTestIPv6Bootstrap()

	// IPv4 address should fail
	addr := netip.MustParseAddr("8.8.8.8")
	_, err := ipv6.ResolveIP(addr)
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("error = %v, want %v", err, ErrInvalidInput)
	}
}

func TestASNBootstrap_ResolveASN(t *testing.T) {
	asn := createTestASNBootstrap()

	tests := []struct {
		name    string
		asn     uint32
		wantURL string
		wantErr error
	}{
		{
			name:    "ASN 1 (ARIN)",
			asn:     1,
			wantURL: "https://rdap.arin.net/registry/",
		},
		{
			name:    "Google ASN",
			asn:     15169,
			wantURL: "https://rdap.arin.net/registry/",
		},
		{
			name:    "RIPE range",
			asn:     28500,
			wantURL: "https://rdap.db.ripe.net/",
		},
		{
			name:    "unknown ASN",
			asn:     999999,
			wantErr: ErrNotFound,
		},
		{
			name:    "zero ASN",
			asn:     0,
			wantErr: ErrInvalidInput,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			urls, err := asn.ResolveASN(tt.asn)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("error = %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(urls) == 0 || urls[0] != tt.wantURL {
				t.Errorf("URL = %v, want %s", urls, tt.wantURL)
			}
		})
	}
}

func TestExtractTLD(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{"example.com", "com"},
		{"www.example.com", "com"},
		{"sub.domain.example.net", "net"},
		{"example.co.uk", "uk"},
		{"com", "com"},
		{"example.com.", "com"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := extractTLD(tt.domain)
			if got != tt.want {
				t.Errorf("extractTLD(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}

func TestResolver_Unified(t *testing.T) {
	bootstrap := &Bootstrap{
		DNS:  createTestDNSBootstrap(),
		IPv4: createTestIPv4Bootstrap(),
		IPv6: createTestIPv6Bootstrap(),
		ASN:  createTestASNBootstrap(),
	}

	resolver := NewResolver(bootstrap)

	// Test domain resolution
	urls, err := resolver.ResolveDomain("example.com")
	if err != nil {
		t.Errorf("ResolveDomain error: %v", err)
	}
	if len(urls) == 0 {
		t.Error("ResolveDomain returned no URLs")
	}

	// Test IPv4 resolution
	urls, err = resolver.ResolveIP("8.8.8.8")
	if err != nil {
		t.Errorf("ResolveIP (IPv4) error: %v", err)
	}
	if len(urls) == 0 {
		t.Error("ResolveIP (IPv4) returned no URLs")
	}

	// Test IPv6 resolution
	urls, err = resolver.ResolveIP("2001:db8::1")
	if err != nil {
		t.Errorf("ResolveIP (IPv6) error: %v", err)
	}
	if len(urls) == 0 {
		t.Error("ResolveIP (IPv6) returned no URLs")
	}

	// Test ASN resolution
	urls, err = resolver.ResolveASN(15169)
	if err != nil {
		t.Errorf("ResolveASN error: %v", err)
	}
	if len(urls) == 0 {
		t.Error("ResolveASN returned no URLs")
	}

	// Test Bootstrap access
	if resolver.Bootstrap() != bootstrap {
		t.Error("Bootstrap() returned wrong instance")
	}
}

func TestResolver_InvalidIP(t *testing.T) {
	bootstrap := &Bootstrap{
		DNS:  createTestDNSBootstrap(),
		IPv4: createTestIPv4Bootstrap(),
		IPv6: createTestIPv6Bootstrap(),
		ASN:  createTestASNBootstrap(),
	}

	resolver := NewResolver(bootstrap)

	_, err := resolver.ResolveIP("invalid")
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("error = %v, want %v", err, ErrInvalidInput)
	}
}

func TestResolver_GetAllRDAPServers(t *testing.T) {
	bootstrap := &Bootstrap{
		DNS:  createTestDNSBootstrap(),
		IPv4: createTestIPv4Bootstrap(),
		IPv6: createTestIPv6Bootstrap(),
		ASN:  createTestASNBootstrap(),
	}

	resolver := NewResolver(bootstrap)

	servers := resolver.GetAllRDAPServers()

	// Should have servers from all bootstrap types
	if len(servers) == 0 {
		t.Error("GetAllRDAPServers() returned empty slice")
	}

	// Check some expected servers are present
	expectedServers := map[string]bool{
		"https://rdap.verisign.com/com/v1/":             false,
		"https://rdap.verisign.com/net/v1/":             false,
		"https://rdap.publicinterestregistry.org/rdap/": false,
		"https://rdap.arin.net/registry/":               false,
		"https://rdap.db.ripe.net/":                     false,
	}

	for _, s := range servers {
		if _, ok := expectedServers[s]; ok {
			expectedServers[s] = true
		}
	}

	for server, found := range expectedServers {
		if !found {
			t.Errorf("expected server %q not found in GetAllRDAPServers()", server)
		}
	}
}

func TestDNSBootstrap_SetTLDURLs(t *testing.T) {
	dns := &DNSBootstrap{
		tldToURLs: make(map[string][]string),
	}

	// Add TLD
	dns.SetTLDURLs("test", []string{"https://rdap.test.com/"})

	urls, err := dns.ResolveTLD("test")
	if err != nil {
		t.Fatalf("ResolveTLD error: %v", err)
	}

	if len(urls) != 1 || urls[0] != "https://rdap.test.com/" {
		t.Errorf("ResolveTLD = %v, want [https://rdap.test.com/]", urls)
	}

	// Override TLD
	dns.SetTLDURLs("test", []string{"https://rdap.test2.com/"})

	urls, err = dns.ResolveTLD("test")
	if err != nil {
		t.Fatalf("ResolveTLD error: %v", err)
	}

	if len(urls) != 1 || urls[0] != "https://rdap.test2.com/" {
		t.Errorf("ResolveTLD = %v, want [https://rdap.test2.com/]", urls)
	}
}

func TestIPv6Bootstrap_ResolveIPString(t *testing.T) {
	ipv6 := createTestIPv6Bootstrap()

	tests := []struct {
		name    string
		addr    string
		wantURL string
		wantErr error
	}{
		{
			name:    "valid IPv6",
			addr:    "2001:db8::1",
			wantURL: "https://rdap.arin.net/registry/",
		},
		{
			name:    "RIPE IPv6",
			addr:    "2a00::1",
			wantURL: "https://rdap.db.ripe.net/",
		},
		{
			name:    "invalid address",
			addr:    "not-an-ip",
			wantErr: ErrInvalidInput,
		},
		{
			name:    "IPv4 address",
			addr:    "8.8.8.8",
			wantErr: ErrInvalidInput,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			urls, err := ipv6.ResolveIPString(tt.addr)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("error = %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(urls) == 0 || urls[0] != tt.wantURL {
				t.Errorf("URL = %v, want %s", urls, tt.wantURL)
			}
		})
	}
}

func TestResolver_GetAllRDAPServers_Empty(t *testing.T) {
	// Test with empty bootstrap
	bootstrap := NewBootstrap()
	resolver := NewResolver(bootstrap)

	servers := resolver.GetAllRDAPServers()
	if servers == nil {
		t.Error("GetAllRDAPServers() returned nil, want empty slice")
	}
	if len(servers) != 0 {
		t.Errorf("GetAllRDAPServers() = %v, want empty slice", servers)
	}
}
