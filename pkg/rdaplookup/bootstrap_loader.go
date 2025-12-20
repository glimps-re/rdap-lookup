package rdaplookup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

// IANA bootstrap file URLs.
const (
	dnsBootstrapURL  = "https://data.iana.org/rdap/dns.json"
	ipv4BootstrapURL = "https://data.iana.org/rdap/ipv4.json"
	ipv6BootstrapURL = "https://data.iana.org/rdap/ipv6.json"
	asnBootstrapURL  = "https://data.iana.org/rdap/asn.json"

	maxBootstrapFileSize = 10 * 1024 * 1024 // 10MB
)

// ianaBootstrapFile represents the structure of IANA bootstrap JSON files.
type ianaBootstrapFile struct {
	Description string  `json:"description"`
	Publication string  `json:"publication"`
	Version     string  `json:"version"`
	Services    [][]any `json:"services"`
}

// load fetches and parses all IANA bootstrap files.
func (b *bootstrapData) load(ctx context.Context, client *http.Client, logger *slog.Logger) error {
	// Load DNS bootstrap
	if err := b.loadDNS(ctx, client, logger); err != nil {
		return fmt.Errorf("loading DNS bootstrap: %w", err)
	}

	// Load IPv4 bootstrap
	if err := b.loadIPv4(ctx, client, logger); err != nil {
		return fmt.Errorf("loading IPv4 bootstrap: %w", err)
	}

	// Load IPv6 bootstrap
	if err := b.loadIPv6(ctx, client, logger); err != nil {
		return fmt.Errorf("loading IPv6 bootstrap: %w", err)
	}

	// Load ASN bootstrap
	if err := b.loadASN(ctx, client, logger); err != nil {
		return fmt.Errorf("loading ASN bootstrap: %w", err)
	}

	// Build the allowed servers list from all bootstrap data for SSRF prevention
	b.buildAllowedServers(logger)

	b.loaded.Store(true)
	return nil
}

// buildAllowedServers collects all RDAP server URLs from bootstrap data
// and builds a normalized allowlist for SSRF prevention.
func (b *bootstrapData) buildAllowedServers(logger *slog.Logger) {
	allowed := make(map[string]struct{})

	b.mu.RLock()

	// Collect from DNS (TLD) servers
	for _, urls := range b.dns.tldToURLs {
		for _, u := range urls {
			if host, err := normalizeServerHost(u); err == nil {
				allowed[host] = struct{}{}
			}
		}
	}

	// Collect from IPv4 servers
	for _, entry := range b.ipv4.prefixes {
		for _, u := range entry.urls {
			if host, err := normalizeServerHost(u); err == nil {
				allowed[host] = struct{}{}
			}
		}
	}

	// Collect from IPv6 servers
	for _, entry := range b.ipv6.prefixes {
		for _, u := range entry.urls {
			if host, err := normalizeServerHost(u); err == nil {
				allowed[host] = struct{}{}
			}
		}
	}

	// Collect from ASN servers
	for _, entry := range b.asn.ranges {
		for _, u := range entry.urls {
			if host, err := normalizeServerHost(u); err == nil {
				allowed[host] = struct{}{}
			}
		}
	}

	b.mu.RUnlock()

	// Update the allowlist
	b.mu.Lock()
	b.allowedServers = allowed
	b.mu.Unlock()

	logger.Debug("SSRF allowlist built",
		slog.Int("allowed_servers", len(allowed)),
	)
}

func (b *bootstrapData) loadDNS(ctx context.Context, client *http.Client, logger *slog.Logger) error {
	data, err := fetchBootstrap(ctx, client, dnsBootstrapURL)
	if err != nil {
		return err
	}

	var file ianaBootstrapFile
	if err := json.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("parsing DNS bootstrap: %w", err)
	}

	tldToURLs := make(map[string][]string)
	for _, service := range file.Services {
		keys, urls, err := parseServiceEntry(service)
		if err != nil {
			continue // Skip malformed entries
		}
		for _, tld := range keys {
			tldToURLs[strings.ToLower(tld)] = urls
		}
	}

	b.mu.Lock()
	b.dns.tldToURLs = tldToURLs
	b.mu.Unlock()

	logger.Debug("DNS bootstrap loaded",
		slog.Int("tlds", len(tldToURLs)),
	)

	return nil
}

func (b *bootstrapData) loadIPv4(ctx context.Context, client *http.Client, logger *slog.Logger) error {
	data, err := fetchBootstrap(ctx, client, ipv4BootstrapURL)
	if err != nil {
		return err
	}

	var file ianaBootstrapFile
	if err := json.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("parsing IPv4 bootstrap: %w", err)
	}

	var prefixes []ipv4Entry
	for _, service := range file.Services {
		keys, urls, err := parseServiceEntry(service)
		if err != nil {
			continue
		}
		for _, key := range keys {
			prefix, err := netip.ParsePrefix(key)
			if err != nil {
				continue
			}
			if !prefix.Addr().Is4() {
				continue
			}
			prefixes = append(prefixes, ipv4Entry{
				prefix: prefix,
				urls:   urls,
			})
		}
	}

	b.mu.Lock()
	b.ipv4.prefixes = prefixes
	b.mu.Unlock()

	logger.Debug("IPv4 bootstrap loaded",
		slog.Int("prefixes", len(prefixes)),
	)

	return nil
}

func (b *bootstrapData) loadIPv6(ctx context.Context, client *http.Client, logger *slog.Logger) error {
	data, err := fetchBootstrap(ctx, client, ipv6BootstrapURL)
	if err != nil {
		return err
	}

	var file ianaBootstrapFile
	if err := json.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("parsing IPv6 bootstrap: %w", err)
	}

	var prefixes []ipv6Entry
	for _, service := range file.Services {
		keys, urls, err := parseServiceEntry(service)
		if err != nil {
			continue
		}
		for _, key := range keys {
			prefix, err := netip.ParsePrefix(key)
			if err != nil {
				continue
			}
			if !prefix.Addr().Is6() {
				continue
			}
			prefixes = append(prefixes, ipv6Entry{
				prefix: prefix,
				urls:   urls,
			})
		}
	}

	b.mu.Lock()
	b.ipv6.prefixes = prefixes
	b.mu.Unlock()

	logger.Debug("IPv6 bootstrap loaded",
		slog.Int("prefixes", len(prefixes)),
	)

	return nil
}

func (b *bootstrapData) loadASN(ctx context.Context, client *http.Client, logger *slog.Logger) error {
	data, err := fetchBootstrap(ctx, client, asnBootstrapURL)
	if err != nil {
		return err
	}

	var file ianaBootstrapFile
	if err := json.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("parsing ASN bootstrap: %w", err)
	}

	var ranges []asnEntry
	for _, service := range file.Services {
		keys, urls, err := parseServiceEntry(service)
		if err != nil {
			continue
		}
		for _, key := range keys {
			start, end, err := parseASNRange(key)
			if err != nil {
				continue
			}
			ranges = append(ranges, asnEntry{
				start: start,
				end:   end,
				urls:  urls,
			})
		}
	}

	b.mu.Lock()
	b.asn.ranges = ranges
	b.mu.Unlock()

	logger.Debug("ASN bootstrap loaded",
		slog.Int("ranges", len(ranges)),
	)

	return nil
}

func fetchBootstrap(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", DefaultStandaloneUserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: status %d", url, resp.StatusCode)
	}

	limitedReader := io.LimitReader(resp.Body, maxBootstrapFileSize)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	return data, nil
}

func parseServiceEntry(service []any) (keys []string, urls []string, err error) {
	if len(service) != 2 {
		return nil, nil, fmt.Errorf("invalid service entry length: %d", len(service))
	}

	keysRaw, ok := service[0].([]any)
	if !ok {
		return nil, nil, fmt.Errorf("invalid keys type")
	}

	urlsRaw, ok := service[1].([]any)
	if !ok {
		return nil, nil, fmt.Errorf("invalid urls type")
	}

	for _, k := range keysRaw {
		if s, ok := k.(string); ok {
			keys = append(keys, s)
		}
	}

	for _, u := range urlsRaw {
		if s, ok := u.(string); ok {
			urls = append(urls, s)
		}
	}

	if len(keys) == 0 || len(urls) == 0 {
		return nil, nil, fmt.Errorf("empty keys or urls")
	}

	return keys, urls, nil
}

func parseASNRange(s string) (start, end uint32, err error) {
	parts := strings.Split(s, "-")
	switch len(parts) {
	case 1:
		n, err := strconv.ParseUint(parts[0], 10, 32)
		if err != nil {
			return 0, 0, err
		}
		return uint32(n), uint32(n), nil
	case 2:
		startN, err := strconv.ParseUint(parts[0], 10, 32)
		if err != nil {
			return 0, 0, err
		}
		endN, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return 0, 0, err
		}
		if startN > endN {
			return 0, 0, fmt.Errorf("invalid ASN range: start > end")
		}
		return uint32(startN), uint32(endN), nil
	default:
		return 0, 0, fmt.Errorf("invalid ASN range format: %s", s)
	}
}
