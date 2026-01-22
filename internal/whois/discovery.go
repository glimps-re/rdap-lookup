package whois

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/glimps-re/rdap-lookup/internal/metrics"
)

// Discovery errors.
var (
	// ErrNoWHOISServer is returned when no WHOIS server is found for a TLD.
	ErrNoWHOISServer = errors.New("no WHOIS server found for TLD")
	// ErrDiscoveryTimeout is returned when WHOIS server discovery times out.
	ErrDiscoveryTimeout = errors.New("WHOIS server discovery timeout")
	// ErrInvalidTLD is returned when an invalid TLD is provided.
	ErrInvalidTLD = errors.New("invalid TLD")
)

const (
	// IANAWHOISServer is the IANA WHOIS server used for TLD discovery.
	IANAWHOISServer = "whois.iana.org"
	// DefaultDiscoveryTimeout is the default timeout for IANA discovery queries.
	DefaultDiscoveryTimeout = 10 * time.Second
	// MaxIANAResponseSize is the maximum size for IANA WHOIS responses.
	MaxIANAResponseSize = 16 * 1024 // 16KB should be enough for IANA responses
)

// WHOISServerEntry represents a cached WHOIS server entry.
type WHOISServerEntry struct {
	// Server is the WHOIS server hostname.
	Server string
	// CachedAt is when this entry was cached.
	CachedAt time.Time
}

// Discovery provides WHOIS server discovery via IANA referral.
// It queries whois.iana.org to find the authoritative WHOIS server for a TLD.
type Discovery struct {
	// cache stores discovered WHOIS servers by TLD.
	cache map[string]*WHOISServerEntry
	mu    sync.RWMutex

	// timeout is the timeout for discovery queries.
	timeout time.Duration
	// cacheTTL is how long to cache discovered servers.
	cacheTTL time.Duration
	// metrics is the metrics collector.
	metrics *metrics.Metrics
}

// DiscoveryOption configures the Discovery service.
type DiscoveryOption func(*Discovery)

// WithDiscoveryTimeout sets the timeout for discovery queries.
func WithDiscoveryTimeout(timeout time.Duration) DiscoveryOption {
	return func(d *Discovery) {
		d.timeout = timeout
	}
}

// WithDiscoveryCacheTTL sets the cache TTL for discovered servers.
func WithDiscoveryCacheTTL(ttl time.Duration) DiscoveryOption {
	return func(d *Discovery) {
		d.cacheTTL = ttl
	}
}

// WithDiscoveryMetrics sets the metrics collector for discovery.
func WithDiscoveryMetrics(m *metrics.Metrics) DiscoveryOption {
	return func(d *Discovery) {
		d.metrics = m
	}
}

// NewDiscovery creates a new WHOIS server discovery service.
func NewDiscovery(opts ...DiscoveryOption) *Discovery {
	d := &Discovery{
		cache:    make(map[string]*WHOISServerEntry),
		timeout:  DefaultDiscoveryTimeout,
		cacheTTL: 24 * time.Hour, // Cache discovered servers for 24 hours
	}

	for _, opt := range opts {
		opt(d)
	}

	return d
}

// DiscoverServer finds the WHOIS server for the given TLD.
// It first checks the cache, then queries whois.iana.org if not cached.
func (d *Discovery) DiscoverServer(ctx context.Context, tld string) (string, error) {
	// Normalize TLD
	tld = normalizeTLD(tld)
	if tld == "" {
		return "", ErrInvalidTLD
	}

	// Check cache first
	if server := d.getCached(tld); server != "" {
		d.recordDiscoveryMetric(tld, "cached")
		return server, nil
	}

	// Query IANA for the WHOIS server
	start := time.Now()
	server, err := d.queryIANA(ctx, tld)
	duration := time.Since(start)

	if d.metrics != nil {
		d.metrics.WHOISDiscoveryDuration.WithLabelValues().Observe(duration.Seconds())
	}

	if err != nil {
		d.recordDiscoveryMetric(tld, "error")
		return "", err
	}

	// Cache the result
	d.setCached(tld, server)
	d.recordDiscoveryMetric(tld, "success")

	return server, nil
}

// getCached returns a cached WHOIS server for the TLD, or empty string if not cached or expired.
func (d *Discovery) getCached(tld string) string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	entry, ok := d.cache[tld]
	if !ok {
		return ""
	}

	// Check if expired
	if time.Since(entry.CachedAt) > d.cacheTTL {
		return ""
	}

	return entry.Server
}

// setCached stores a WHOIS server in the cache.
func (d *Discovery) setCached(tld, server string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.cache[tld] = &WHOISServerEntry{
		Server:   server,
		CachedAt: time.Now(),
	}

	if d.metrics != nil {
		d.metrics.WHOISServersCached.Set(float64(len(d.cache)))
	}
}

// queryIANA queries whois.iana.org for the WHOIS server of the given TLD.
func (d *Discovery) queryIANA(ctx context.Context, tld string) (string, error) {
	// Apply timeout
	timeout := d.timeout
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining < timeout {
			timeout = remaining
		}
	}

	// Create a context with timeout if not already set
	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Dial the IANA WHOIS server
	var dialer net.Dialer
	conn, err := dialer.DialContext(queryCtx, "tcp", IANAWHOISServer+":43")
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return "", ErrDiscoveryTimeout
		}
		return "", &WHOISError{Op: "dial", Server: IANAWHOISServer, Err: err}
	}
	defer func() {
		_ = conn.Close()
	}()

	// Set read/write deadline
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", &WHOISError{Op: "set deadline", Server: IANAWHOISServer, Err: err}
	}

	// Send the query (just the TLD followed by CRLF)
	query := tld + "\r\n"
	if _, err := conn.Write([]byte(query)); err != nil {
		return "", &WHOISError{Op: "write", Server: IANAWHOISServer, Err: err}
	}

	// Read the response with size limit using streaming approach
	return d.parseIANAResponse(io.LimitReader(conn, MaxIANAResponseSize))
}

// parseIANAResponse parses an IANA WHOIS response to extract the WHOIS server.
// IANA responses contain a "whois:" field with the authoritative WHOIS server.
func (d *Discovery) parseIANAResponse(reader io.Reader) (string, error) {
	scanner := bufio.NewScanner(reader)
	// Set a reasonable max token size
	buf := make([]byte, 4096)
	scanner.Buffer(buf, 4096)

	for scanner.Scan() {
		line := scanner.Text()

		// Look for the "whois:" field
		// IANA format: "whois:        whois.example.com"
		if strings.HasPrefix(strings.ToLower(line), "whois:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				server := strings.TrimSpace(parts[1])
				if server != "" {
					return server, nil
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", &WHOISError{Op: "read", Server: IANAWHOISServer, Err: err}
	}

	return "", ErrNoWHOISServer
}

// ClearCache clears all cached WHOIS servers.
func (d *Discovery) ClearCache() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.cache = make(map[string]*WHOISServerEntry)

	if d.metrics != nil {
		d.metrics.WHOISServersCached.Set(0)
	}
}

// CacheSize returns the number of cached WHOIS servers.
func (d *Discovery) CacheSize() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.cache)
}

// recordDiscoveryMetric records a discovery metric.
func (d *Discovery) recordDiscoveryMetric(tld, status string) {
	if d.metrics != nil {
		d.metrics.WHOISDiscoveryTotal.WithLabelValues(tld, status).Inc()
	}
}

// normalizeTLD normalizes a TLD by removing leading dots and converting to lowercase.
func normalizeTLD(tld string) string {
	// Remove leading dot if present
	tld = strings.TrimPrefix(tld, ".")
	// Convert to lowercase
	tld = strings.ToLower(tld)
	// Trim whitespace
	tld = strings.TrimSpace(tld)

	if tld == "" {
		return ""
	}

	// Validate: TLD should only contain alphanumeric characters and hyphens
	for _, r := range tld {
		if !isValidTLDChar(r) {
			return ""
		}
	}

	return tld
}

// isValidTLDChar checks if a character is valid in a TLD.
// Allows dots for compound TLDs like "com.au" and "co.uk".
func isValidTLDChar(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.'
}

// ExtractTLD extracts the TLD from a domain name.
// For "example.com" returns "com".
// For "sub.example.co.uk" returns "uk".
func ExtractTLD(domain string) string {
	// Remove trailing dot if present
	domain = strings.TrimSuffix(domain, ".")
	domain = strings.TrimSpace(domain)

	if domain == "" {
		return ""
	}

	// Find the last label
	lastDot := strings.LastIndex(domain, ".")
	if lastDot == -1 {
		// No dot, the whole thing might be a TLD
		return domain
	}

	return domain[lastDot+1:]
}
