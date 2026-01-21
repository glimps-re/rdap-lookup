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

	"github.com/glimps-re/rdap-lookup/internal/config"
	"github.com/glimps-re/rdap-lookup/internal/metrics"
)

// Client errors.
var (
	// ErrQueryTimeout is returned when a WHOIS query times out.
	ErrQueryTimeout = errors.New("WHOIS query timeout")
	// ErrResponseTooLarge is returned when the WHOIS response exceeds the size limit.
	ErrResponseTooLarge = errors.New("WHOIS response too large")
	// ErrDomainNotFound is returned when the domain is not found.
	ErrDomainNotFound = errors.New("domain not found")
	// ErrServerNotAvailable is returned when the WHOIS server is not available.
	ErrServerNotAvailable = errors.New("WHOIS server not available")
)

const (
	// WHOISPort is the standard WHOIS protocol port.
	WHOISPort = "43"
	// DefaultQueryTimeout is the default timeout for WHOIS queries.
	DefaultQueryTimeout = 10 * time.Second
	// DefaultMaxResponseSize is the default maximum response size (64KB).
	DefaultMaxResponseSize = 64 * 1024
	// ReadBufferSize is the buffer size for reading responses.
	ReadBufferSize = 4096
)

// Client is a WHOIS protocol client.
type Client struct {
	// discovery is used to find WHOIS servers for TLDs.
	discovery *Discovery
	// timeout is the query timeout.
	timeout time.Duration
	// maxResponseSize is the maximum response size in bytes.
	maxResponseSize int64
	// metrics is the metrics collector.
	metrics *metrics.Metrics

	// mu protects the closed flag.
	mu     sync.RWMutex
	closed bool
}

// ClientOption configures the Client.
type ClientOption func(*Client)

// WithClientTimeout sets the query timeout.
func WithClientTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.timeout = timeout
	}
}

// WithClientMaxResponseSize sets the maximum response size.
func WithClientMaxResponseSize(maxSize int64) ClientOption {
	return func(c *Client) {
		c.maxResponseSize = maxSize
	}
}

// WithClientMetrics sets the metrics collector.
func WithClientMetrics(m *metrics.Metrics) ClientOption {
	return func(c *Client) {
		c.metrics = m
	}
}

// WithClientDiscovery sets a custom discovery service.
func WithClientDiscovery(d *Discovery) ClientOption {
	return func(c *Client) {
		c.discovery = d
	}
}

// NewClient creates a new WHOIS client.
func NewClient(opts ...ClientOption) *Client {
	c := &Client{
		timeout:         DefaultQueryTimeout,
		maxResponseSize: DefaultMaxResponseSize,
	}

	for _, opt := range opts {
		opt(c)
	}

	// Create default discovery if not provided
	if c.discovery == nil {
		discoveryOpts := []DiscoveryOption{
			WithDiscoveryTimeout(c.timeout),
		}
		if c.metrics != nil {
			discoveryOpts = append(discoveryOpts, WithDiscoveryMetrics(c.metrics))
		}
		c.discovery = NewDiscovery(discoveryOpts...)
	}

	return c
}

// NewClientFromConfig creates a new WHOIS client from configuration.
func NewClientFromConfig(cfg config.WHOISConfig, m *metrics.Metrics) *Client {
	return NewClient(
		WithClientTimeout(cfg.Timeout),
		WithClientMaxResponseSize(cfg.MaxResponseSize),
		WithClientMetrics(m),
	)
}

// Query performs a WHOIS query for the given domain.
// It automatically discovers the appropriate WHOIS server for the TLD.
func (c *Client) Query(ctx context.Context, domain string) (*QueryResult, error) {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return nil, &WHOISError{Op: "query", Err: errors.New("client closed")}
	}
	c.mu.RUnlock()

	// Normalize and validate domain
	domain = normalizeDomain(domain)
	if domain == "" {
		return nil, &WHOISError{Op: "query", Err: errors.New("invalid domain")}
	}

	// Extract TLD and discover WHOIS server
	tld := ExtractTLD(domain)
	if tld == "" {
		return nil, &WHOISError{Op: "query", Err: errors.New("cannot extract TLD from domain")}
	}

	server, err := c.discovery.DiscoverServer(ctx, tld)
	if err != nil {
		return nil, &WHOISError{Op: "discover", Err: err}
	}

	// Query the discovered server
	return c.QueryServer(ctx, domain, server)
}

// QueryServer performs a WHOIS query against a specific server.
func (c *Client) QueryServer(ctx context.Context, domain, server string) (*QueryResult, error) {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return nil, &WHOISError{Op: "query", Server: server, Err: errors.New("client closed")}
	}
	c.mu.RUnlock()

	start := time.Now()

	// Apply timeout
	timeout := c.timeout
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining < timeout {
			timeout = remaining
		}
	}

	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Perform the query
	response, err := c.doQuery(queryCtx, domain, server)
	duration := time.Since(start)

	// Record metrics
	c.recordQueryMetrics(server, err, duration)

	if err != nil {
		return nil, err
	}

	result := &QueryResult{
		Server:   server,
		Response: response,
		Duration: duration,
		Cached:   false,
	}

	// Record response size metric
	if c.metrics != nil {
		c.metrics.WHOISResponseSizeBytes.WithLabelValues(server).Observe(float64(len(response)))
	}

	return result, nil
}

// doQuery performs the actual WHOIS query.
func (c *Client) doQuery(ctx context.Context, domain, server string) (string, error) {
	return c.doQueryAddr(ctx, domain, server, net.JoinHostPort(server, WHOISPort))
}

// doQueryAddr performs a WHOIS query to a specific address.
// This is used internally and for testing with custom ports.
func (c *Client) doQueryAddr(ctx context.Context, domain, server, addr string) (string, error) {
	// Dial with context
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return "", ErrQueryTimeout
		}
		return "", &WHOISError{Op: "dial", Server: server, Err: err}
	}
	defer func() {
		_ = conn.Close()
	}()

	// Set deadline from context
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return "", &WHOISError{Op: "set deadline", Server: server, Err: err}
		}
	}

	// Build and send query with server-specific formatting
	query := buildServerQuery(domain, server)
	if _, err := conn.Write([]byte(query)); err != nil {
		return "", &WHOISError{Op: "write", Server: server, Err: err}
	}

	// Read response with size limit using streaming approach
	response, err := c.readResponse(conn, server)
	if err != nil {
		return "", err
	}

	return response, nil
}

// readResponse reads the WHOIS response with streaming and size limits.
// This avoids using io.ReadAll and processes data in chunks.
func (c *Client) readResponse(conn net.Conn, server string) (string, error) {
	// Create a limited reader to prevent memory exhaustion
	limitedReader := io.LimitReader(conn, c.maxResponseSize+1)
	reader := bufio.NewReaderSize(limitedReader, ReadBufferSize)

	var builder strings.Builder
	builder.Grow(ReadBufferSize) // Pre-allocate some space

	buf := make([]byte, ReadBufferSize)
	totalRead := int64(0)

	for {
		n, err := reader.Read(buf)
		if n > 0 {
			totalRead += int64(n)

			// Check size limit
			if totalRead > c.maxResponseSize {
				return "", ErrResponseTooLarge
			}

			builder.Write(buf[:n])
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return "", &WHOISError{Op: "read", Server: server, Err: err}
		}
	}

	return builder.String(), nil
}

// recordQueryMetrics records query metrics.
func (c *Client) recordQueryMetrics(server string, err error, duration time.Duration) {
	if c.metrics == nil {
		return
	}

	// Record duration
	c.metrics.WHOISRequestDuration.WithLabelValues(server).Observe(duration.Seconds())

	// Determine status
	status := "success"
	if err != nil {
		if errors.Is(err, ErrQueryTimeout) || errors.Is(err, context.DeadlineExceeded) {
			status = "timeout"
		} else {
			status = "error"
		}
	}
	c.metrics.WHOISRequestsTotal.WithLabelValues(server, status).Inc()
}

// Close closes the client and releases resources.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true

	// Clear discovery cache
	if c.discovery != nil {
		c.discovery.ClearCache()
	}

	return nil
}

// Discovery returns the discovery service used by the client.
func (c *Client) Discovery() *Discovery {
	return c.discovery
}

// normalizeDomain normalizes a domain name for WHOIS queries.
func normalizeDomain(domain string) string {
	// Remove leading/trailing whitespace
	domain = strings.TrimSpace(domain)
	// Convert to lowercase
	domain = strings.ToLower(domain)
	// Remove trailing dot
	domain = strings.TrimSuffix(domain, ".")

	if domain == "" {
		return ""
	}

	// Basic validation: domain should contain at least one dot
	// (single-label queries are typically not valid for domain WHOIS)
	if !strings.Contains(domain, ".") {
		return ""
	}

	return domain
}

// buildServerQuery builds a server-specific WHOIS query string.
// Different WHOIS servers have different query formats to retrieve full data.
func buildServerQuery(domain, server string) string {
	// Server-specific query formats
	switch {
	case strings.HasSuffix(server, ".denic.de") || server == "whois.denic.de":
		// DENIC (.de) requires -T dn flag for full domain data
		// Without this flag, only minimal data (domain name, status) is returned
		return "-T dn " + domain + "\r\n"

	case strings.HasSuffix(server, ".jprs.jp") || server == "whois.jprs.jp":
		// JPRS (.jp) uses "DOM" prefix for domain queries
		return "DOM " + domain + "/e\r\n"

	case strings.HasSuffix(server, ".nic.ad.jp") || server == "whois.nic.ad.jp":
		// NIC.AD.JP also uses /e suffix for English output
		return domain + "/e\r\n"

	case strings.Contains(server, "whois.verisign"):
		// Verisign (.com, .net) - use "domain" prefix for exact match
		return "domain " + domain + "\r\n"

	case server == "whois.arin.net":
		// ARIN - use "n" prefix for network queries, but for domains use standard
		return "n + " + domain + "\r\n"

	default:
		// Standard WHOIS query format
		return domain + "\r\n"
	}
}
