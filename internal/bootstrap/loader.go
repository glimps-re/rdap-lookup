package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yl2chen/cidranger"
)

const (
	// IANA bootstrap file URLs.
	//
	// Security Note: Certificate pinning is NOT implemented for IANA bootstrap fetches.
	// Trade-off rationale:
	// - IANA uses well-known Certificate Authorities with proper certificate management
	// - Standard HTTPS/TLS verification provides reasonable security against MITM
	// - Certificate pinning would require pin rotation infrastructure and increase
	//   operational complexity (pins must be updated before IANA rotates certificates)
	// - Risk is mitigated by logging SHA256 checksums of all fetched data for audit
	// - In high-security environments, consider using a local bootstrap file instead
	dnsBootstrapURL  = "https://data.iana.org/rdap/dns.json"
	ipv4BootstrapURL = "https://data.iana.org/rdap/ipv4.json"
	ipv6BootstrapURL = "https://data.iana.org/rdap/ipv6.json"
	asnBootstrapURL  = "https://data.iana.org/rdap/asn.json"

	// maxBootstrapFileSize limits the size of bootstrap files to prevent DoS.
	maxBootstrapFileSize = 10 * 1024 * 1024 // 10MB
)

// Loader fetches and parses IANA bootstrap files.
type Loader struct {
	client  *http.Client
	timeout time.Duration
	logger  *slog.Logger
}

// NewLoader creates a new bootstrap loader with the given timeout.
func NewLoader(timeout time.Duration) *Loader {
	return &Loader{
		client: &http.Client{
			Timeout: timeout,
		},
		timeout: timeout,
		logger:  slog.Default(),
	}
}

// SetLogger sets the logger for the loader.
func (l *Loader) SetLogger(logger *slog.Logger) {
	l.logger = logger
}

// LoadAll loads all bootstrap files and returns a populated Bootstrap.
func (l *Loader) LoadAll(ctx context.Context) (*Bootstrap, error) {
	b := NewBootstrap()

	// Load DNS bootstrap
	if err := l.LoadDNS(ctx, b.DNS); err != nil {
		return nil, fmt.Errorf("loading DNS bootstrap: %w", err)
	}

	// Load IPv4 bootstrap
	if err := l.LoadIPv4(ctx, b.IPv4); err != nil {
		return nil, fmt.Errorf("loading IPv4 bootstrap: %w", err)
	}

	// Load IPv6 bootstrap
	if err := l.LoadIPv6(ctx, b.IPv6); err != nil {
		return nil, fmt.Errorf("loading IPv6 bootstrap: %w", err)
	}

	// Load ASN bootstrap
	if err := l.LoadASN(ctx, b.ASN); err != nil {
		return nil, fmt.Errorf("loading ASN bootstrap: %w", err)
	}

	return b, nil
}

// LoadDNS fetches and parses the DNS bootstrap file.
func (l *Loader) LoadDNS(ctx context.Context, dns *DNSBootstrap) error {
	data, err := l.fetch(ctx, dnsBootstrapURL)
	if err != nil {
		return err
	}

	var file IANABootstrapFile
	if err := json.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("parsing DNS bootstrap JSON: %w", err)
	}

	tldToURLs := make(map[string][]string)
	for _, service := range file.Services {
		entry, err := parseServiceEntry(service)
		if err != nil {
			continue // Skip malformed entries
		}
		for _, tld := range entry.Keys {
			// Store TLDs in lowercase for case-insensitive lookup
			tldToURLs[strings.ToLower(tld)] = entry.URLs
		}
	}

	dns.mu.Lock()
	dns.tldToURLs = tldToURLs
	dns.lastRefresh = time.Now()
	dns.publication = file.Publication
	dns.version = file.Version
	dns.mu.Unlock()

	return nil
}

// LoadIPv4 fetches and parses the IPv4 bootstrap file.
func (l *Loader) LoadIPv4(ctx context.Context, ipv4 *IPv4Bootstrap) error {
	data, err := l.fetch(ctx, ipv4BootstrapURL)
	if err != nil {
		return err
	}

	var file IANABootstrapFile
	if err := json.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("parsing IPv4 bootstrap JSON: %w", err)
	}

	// Build both slice (for iteration) and ranger (for fast lookup)
	var prefixes []ipv4Entry
	ranger := cidranger.NewPCTrieRanger()

	for _, service := range file.Services {
		entry, err := parseServiceEntry(service)
		if err != nil {
			continue
		}
		for _, key := range entry.Keys {
			prefix, err := netip.ParsePrefix(key)
			if err != nil {
				continue // Skip invalid prefixes
			}
			if !prefix.Addr().Is4() {
				continue // Skip non-IPv4
			}

			// Add to slice for iteration
			prefixes = append(prefixes, ipv4Entry{
				prefix: prefix,
				urls:   entry.URLs,
			})

			// Add to ranger for fast lookup
			ipNet := prefixToIPNet(prefix)
			if err := ranger.Insert(&ipv4RangerEntry{network: ipNet, urls: entry.URLs}); err != nil {
				l.logger.Warn("failed to insert IPv4 prefix into ranger",
					slog.String("prefix", key),
					slog.String("error", err.Error()),
				)
			}
		}
	}

	ipv4.mu.Lock()
	ipv4.ranger = ranger
	ipv4.prefixes = prefixes
	ipv4.lastRefresh = time.Now()
	ipv4.publication = file.Publication
	ipv4.version = file.Version
	ipv4.mu.Unlock()

	return nil
}

// LoadIPv6 fetches and parses the IPv6 bootstrap file.
func (l *Loader) LoadIPv6(ctx context.Context, ipv6 *IPv6Bootstrap) error {
	data, err := l.fetch(ctx, ipv6BootstrapURL)
	if err != nil {
		return err
	}

	var file IANABootstrapFile
	if err := json.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("parsing IPv6 bootstrap JSON: %w", err)
	}

	// Build both slice (for iteration) and ranger (for fast lookup)
	var prefixes []ipv6Entry
	ranger := cidranger.NewPCTrieRanger()

	for _, service := range file.Services {
		entry, err := parseServiceEntry(service)
		if err != nil {
			continue
		}
		for _, key := range entry.Keys {
			prefix, err := netip.ParsePrefix(key)
			if err != nil {
				continue
			}
			if !prefix.Addr().Is6() {
				continue
			}

			// Add to slice for iteration
			prefixes = append(prefixes, ipv6Entry{
				prefix: prefix,
				urls:   entry.URLs,
			})

			// Add to ranger for fast lookup
			ipNet := prefixToIPNet(prefix)
			if err := ranger.Insert(&ipv6RangerEntry{network: ipNet, urls: entry.URLs}); err != nil {
				l.logger.Warn("failed to insert IPv6 prefix into ranger",
					slog.String("prefix", key),
					slog.String("error", err.Error()),
				)
			}
		}
	}

	ipv6.mu.Lock()
	ipv6.ranger = ranger
	ipv6.prefixes = prefixes
	ipv6.lastRefresh = time.Now()
	ipv6.publication = file.Publication
	ipv6.version = file.Version
	ipv6.mu.Unlock()

	return nil
}

// LoadASN fetches and parses the ASN bootstrap file.
func (l *Loader) LoadASN(ctx context.Context, asn *ASNBootstrap) error {
	data, err := l.fetch(ctx, asnBootstrapURL)
	if err != nil {
		return err
	}

	var file IANABootstrapFile
	if err := json.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("parsing ASN bootstrap JSON: %w", err)
	}

	var ranges []asnEntry
	for _, service := range file.Services {
		entry, err := parseServiceEntry(service)
		if err != nil {
			continue
		}
		for _, key := range entry.Keys {
			start, end, err := parseASNRange(key)
			if err != nil {
				continue
			}
			ranges = append(ranges, asnEntry{
				start: start,
				end:   end,
				urls:  entry.URLs,
			})
		}
	}

	// Sort ranges by start ASN for binary search in ResolveASN
	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].start < ranges[j].start
	})

	asn.mu.Lock()
	asn.ranges = ranges
	asn.lastRefresh = time.Now()
	asn.publication = file.Publication
	asn.version = file.Version
	asn.mu.Unlock()

	return nil
}

// fetch retrieves a bootstrap file from the given URL.
func (l *Loader) fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "rdap-lookup/1.0")

	resp, err := l.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: status %d", url, resp.StatusCode)
	}

	// Limit read size to prevent DoS
	limitedReader := io.LimitReader(resp.Body, maxBootstrapFileSize)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	// Compute and log checksum for audit trail
	checksum := sha256.Sum256(data)
	l.logger.Info("bootstrap data loaded",
		slog.String("source", url),
		slog.String("sha256", hex.EncodeToString(checksum[:])),
		slog.Int("size_bytes", len(data)),
	)

	return data, nil
}

// parseServiceEntry parses a service entry from the IANA bootstrap format.
// Each entry is an array: [[keys...], [urls...]]
func parseServiceEntry(service []any) (ServiceEntry, error) {
	if len(service) != 2 {
		return ServiceEntry{}, fmt.Errorf("invalid service entry length: %d", len(service))
	}

	keysRaw, ok := service[0].([]any)
	if !ok {
		return ServiceEntry{}, errors.New("invalid keys type")
	}

	urlsRaw, ok := service[1].([]any)
	if !ok {
		return ServiceEntry{}, errors.New("invalid urls type")
	}

	keys := make([]string, 0, len(keysRaw))
	for _, k := range keysRaw {
		if s, ok := k.(string); ok {
			keys = append(keys, s)
		}
	}

	urls := make([]string, 0, len(urlsRaw))
	for _, u := range urlsRaw {
		if s, ok := u.(string); ok {
			urls = append(urls, s)
		}
	}

	if len(keys) == 0 || len(urls) == 0 {
		return ServiceEntry{}, errors.New("empty keys or urls")
	}

	return ServiceEntry{Keys: keys, URLs: urls}, nil
}

// parseASNRange parses an ASN range string like "1234" or "1234-5678".
func parseASNRange(s string) (start, end uint32, err error) {
	parts := strings.Split(s, "-")
	switch len(parts) {
	case 1:
		// Single ASN
		n, err := strconv.ParseUint(parts[0], 10, 32)
		if err != nil {
			return 0, 0, err
		}
		return uint32(n), uint32(n), nil
	case 2:
		// Range
		startN, err := strconv.ParseUint(parts[0], 10, 32)
		if err != nil {
			return 0, 0, err
		}
		endN, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return 0, 0, err
		}
		if startN > endN {
			return 0, 0, errors.New("invalid ASN range: start > end")
		}
		return uint32(startN), uint32(endN), nil
	default:
		return 0, 0, fmt.Errorf("invalid ASN range format: %s", s)
	}
}
