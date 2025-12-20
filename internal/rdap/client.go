// Package rdap provides an HTTP client for querying RDAP servers.
// It supports domain, IP, ASN, entity, and nameserver lookups with
// configurable timeouts and retry logic.
package rdap

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/glimps-re/rdap-lookup/internal/bootstrap"
	"github.com/glimps-re/rdap-lookup/internal/metrics"
)

// Common errors returned by the RDAP client.
var (
	ErrNoServers        = errors.New("no RDAP servers available")
	ErrAllServersFailed = errors.New("all RDAP servers failed")
	ErrNotFound         = errors.New("object not found")
	ErrRateLimited      = errors.New("rate limited by RDAP server")
	ErrServerError      = errors.New("RDAP server error")
	ErrInvalidResponse  = errors.New("invalid RDAP response")
	ErrRequestTimeout   = errors.New("request timeout")
)

// QueryType represents the type of RDAP query.
type QueryType string

const (
	QueryTypeDomain     QueryType = "domain"
	QueryTypeIP         QueryType = "ip"
	QueryTypeASN        QueryType = "autnum"
	QueryTypeEntity     QueryType = "entity"
	QueryTypeNameserver QueryType = "nameserver"
)

// maxResponseSize limits RDAP response size to prevent memory exhaustion.
const maxResponseSize = 10 * 1024 * 1024 // 10MB

// backoffMultipliers provides pre-calculated backoff durations to avoid integer overflow.
// Values: 100ms, 200ms, 400ms, 800ms, 1.6s, 3.2s
var backoffMultipliers = []time.Duration{
	100 * time.Millisecond,
	200 * time.Millisecond,
	400 * time.Millisecond,
	800 * time.Millisecond,
	1600 * time.Millisecond,
	3200 * time.Millisecond,
}

// calculateBackoff returns the backoff duration for a retry attempt.
// attempt should be >= 1 (first retry).
func calculateBackoff(attempt int) time.Duration {
	idx := attempt - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(backoffMultipliers) {
		idx = len(backoffMultipliers) - 1
	}
	return backoffMultipliers[idx]
}

// Client is an HTTP client for RDAP queries.
type Client struct {
	httpClient *http.Client
	resolver   *bootstrap.Resolver
	logger     *slog.Logger
	metrics    *metrics.Metrics
	maxRetries int
	userAgent  string
}

// ClientOption configures a Client.
type ClientOption func(*Client)

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(c *http.Client) ClientOption {
	return func(client *Client) {
		client.httpClient = c
	}
}

// WithResolver sets the bootstrap resolver.
func WithResolver(r *bootstrap.Resolver) ClientOption {
	return func(client *Client) {
		client.resolver = r
	}
}

// WithLogger sets the logger.
func WithLogger(l *slog.Logger) ClientOption {
	return func(client *Client) {
		client.logger = l
	}
}

// WithMetrics sets the metrics collector.
func WithMetrics(m *metrics.Metrics) ClientOption {
	return func(client *Client) {
		client.metrics = m
	}
}

// WithMaxRetries sets the maximum number of retries.
func WithMaxRetries(n int) ClientOption {
	return func(client *Client) {
		client.maxRetries = n
	}
}

// WithUserAgent sets the User-Agent header.
func WithUserAgent(ua string) ClientOption {
	return func(client *Client) {
		client.userAgent = ua
	}
}

// maxRedirects limits the number of HTTP redirects to prevent redirect loops.
const maxRedirects = 3

// NewClient creates a new RDAP client with the given timeout.
func NewClient(timeout time.Duration, opts ...ClientOption) *Client {
	c := &Client{
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
			CheckRedirect: func(_ *http.Request, via []*http.Request) error {
				if len(via) >= maxRedirects {
					return fmt.Errorf("stopped after %d redirects", len(via))
				}
				return nil
			},
		},
		maxRetries: 2,
		userAgent:  "rdap-lookup/1.0",
		logger:     slog.Default(),
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// SetResolver updates the bootstrap resolver.
// This is useful when bootstrap data is refreshed.
func (c *Client) SetResolver(r *bootstrap.Resolver) {
	c.resolver = r
}

// QueryDomain queries RDAP for domain information.
func (c *Client) QueryDomain(ctx context.Context, domain string) (*DomainResponse, error) {
	if domain == "" {
		return nil, bootstrap.ErrInvalidInput
	}

	// Normalize domain
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	// Get RDAP server URLs from bootstrap
	urls, err := c.resolver.ResolveDomain(domain)
	if err != nil {
		return nil, fmt.Errorf("resolve domain %q: %w", domain, err)
	}

	if len(urls) == 0 {
		return nil, ErrNoServers
	}

	// Build query path
	path := "domain/" + url.PathEscape(domain)

	// Try each server
	var resp DomainResponse
	if err := c.queryWithRetry(ctx, QueryTypeDomain, urls, path, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// QueryIP queries RDAP for IP network information.
func (c *Client) QueryIP(ctx context.Context, ip string) (*IPResponse, error) {
	if ip == "" {
		return nil, bootstrap.ErrInvalidInput
	}

	// Get RDAP server URLs from bootstrap
	urls, err := c.resolver.ResolveIP(ip)
	if err != nil {
		return nil, fmt.Errorf("resolve IP %q: %w", ip, err)
	}

	if len(urls) == 0 {
		return nil, ErrNoServers
	}

	// Build query path
	path := "ip/" + url.PathEscape(ip)

	// Try each server
	var resp IPResponse
	if err := c.queryWithRetry(ctx, QueryTypeIP, urls, path, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// QueryASN queries RDAP for autonomous system number information.
func (c *Client) QueryASN(ctx context.Context, asn uint32) (*ASNResponse, error) {
	if asn == 0 {
		return nil, bootstrap.ErrInvalidInput
	}

	// Get RDAP server URLs from bootstrap
	urls, err := c.resolver.ResolveASN(asn)
	if err != nil {
		return nil, fmt.Errorf("resolve ASN %d: %w", asn, err)
	}

	if len(urls) == 0 {
		return nil, ErrNoServers
	}

	// Build query path
	path := fmt.Sprintf("autnum/%d", asn)

	// Try each server
	var resp ASNResponse
	if err := c.queryWithRetry(ctx, QueryTypeASN, urls, path, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// QueryEntity queries RDAP for entity (registrar/registrant) information.
// Note: Entity queries require a known RDAP server URL since entities
// are not directly bootstrappable via IANA.
func (c *Client) QueryEntity(ctx context.Context, handle string, serverURL string) (*EntityResponse, error) {
	if handle == "" {
		return nil, bootstrap.ErrInvalidInput
	}

	if serverURL == "" {
		return nil, ErrNoServers
	}

	// Build query path
	path := "entity/" + url.PathEscape(handle)

	// Try the server
	var resp EntityResponse
	if err := c.queryWithRetry(ctx, QueryTypeEntity, []string{serverURL}, path, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// QueryNameserver queries RDAP for nameserver information.
func (c *Client) QueryNameserver(ctx context.Context, nameserver string) (*NameserverResponse, error) {
	if nameserver == "" {
		return nil, bootstrap.ErrInvalidInput
	}

	// Normalize nameserver
	nameserver = strings.ToLower(strings.TrimSuffix(nameserver, "."))

	// Get RDAP server URLs from bootstrap (use domain's TLD)
	urls, err := c.resolver.ResolveDomain(nameserver)
	if err != nil {
		return nil, fmt.Errorf("resolve nameserver %q: %w", nameserver, err)
	}

	if len(urls) == 0 {
		return nil, ErrNoServers
	}

	// Build query path
	path := "nameserver/" + url.PathEscape(nameserver)

	// Try each server
	var resp NameserverResponse
	if err := c.queryWithRetry(ctx, QueryTypeNameserver, urls, path, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// extractServerHost extracts the hostname from a URL for metric labels.
func extractServerHost(serverURL string) string {
	parsed, err := url.Parse(serverURL)
	if err != nil {
		return "unknown"
	}
	return parsed.Host
}

// queryWithRetry attempts to query RDAP servers with retry logic.
func (c *Client) queryWithRetry(ctx context.Context, queryType QueryType, serverURLs []string, path string, result any) error {
	var lastErr error

	for _, baseURL := range serverURLs {
		// Normalize base URL
		if !strings.HasSuffix(baseURL, "/") {
			baseURL += "/"
		}

		fullURL := baseURL + path
		serverHost := extractServerHost(baseURL)

		for attempt := 0; attempt <= c.maxRetries; attempt++ {
			if attempt > 0 {
				// Record retry metric
				if c.metrics != nil {
					c.metrics.RDAPUpstreamRetriesTotal.WithLabelValues(serverHost).Inc()
				}

				// Exponential backoff: 100ms, 200ms, 400ms... capped at 3.2s
				backoff := calculateBackoff(attempt)
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(backoff):
				}
			}

			err := c.doQuery(ctx, queryType, fullURL, serverHost, result)
			if err == nil {
				return nil
			}

			lastErr = err

			// Don't retry on certain errors
			if errors.Is(err, ErrNotFound) ||
				errors.Is(err, context.Canceled) ||
				errors.Is(err, context.DeadlineExceeded) {
				return err
			}

			c.logger.Debug("RDAP query failed, retrying",
				slog.String("url", fullURL),
				slog.Int("attempt", attempt+1),
				slog.String("error", err.Error()),
			)
		}
	}

	if lastErr != nil {
		return fmt.Errorf("%w: %w", ErrAllServersFailed, lastErr)
	}

	return ErrAllServersFailed
}

// doQuery performs a single RDAP query.
func (c *Client) doQuery(ctx context.Context, queryType QueryType, queryURL string, serverHost string, result any) error {
	start := time.Now()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, queryURL, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Record error metrics
		if c.metrics != nil {
			errorType := "connection"
			if errors.Is(err, context.DeadlineExceeded) {
				errorType = "timeout"
			}
			c.metrics.RDAPUpstreamErrorsTotal.WithLabelValues(serverHost, errorType).Inc()
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return ErrRequestTimeout
		}
		return fmt.Errorf("http request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	duration := time.Since(start)

	// Record metrics
	if c.metrics != nil {
		// Per-type metrics
		c.metrics.RDAPClientRequestDuration.WithLabelValues(string(queryType)).Observe(duration.Seconds())
		c.metrics.RDAPClientRequestsTotal.WithLabelValues(string(queryType), fmt.Sprintf("%d", resp.StatusCode)).Inc()

		// Per-server metrics
		c.metrics.RDAPUpstreamRequestDuration.WithLabelValues(serverHost).Observe(duration.Seconds())
		c.metrics.RDAPUpstreamRequestsTotal.WithLabelValues(serverHost, fmt.Sprintf("%d", resp.StatusCode)).Inc()
	}

	c.logger.Debug("RDAP query completed",
		slog.String("url", queryURL),
		slog.Int("status", resp.StatusCode),
		slog.Duration("duration", duration),
	)

	// Handle response status
	switch resp.StatusCode {
	case http.StatusOK:
		// Success, parse response below
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusTooManyRequests:
		if c.metrics != nil {
			c.metrics.RDAPUpstreamRateLimited.WithLabelValues(serverHost).Inc()
		}
		return ErrRateLimited
	case http.StatusBadRequest:
		if c.metrics != nil {
			c.metrics.RDAPUpstreamErrorsTotal.WithLabelValues(serverHost, "bad_request").Inc()
		}
		return fmt.Errorf("%w: bad request", ErrInvalidResponse)
	default:
		if resp.StatusCode >= 500 {
			if c.metrics != nil {
				c.metrics.RDAPUpstreamErrorsTotal.WithLabelValues(serverHost, "server_error").Inc()
			}
			return fmt.Errorf("%w: status %d", ErrServerError, resp.StatusCode)
		}
		if c.metrics != nil {
			c.metrics.RDAPUpstreamErrorsTotal.WithLabelValues(serverHost, "other").Inc()
		}
		return fmt.Errorf("%w: status %d", ErrInvalidResponse, resp.StatusCode)
	}

	// Read response with size limit
	limitedReader := io.LimitReader(resp.Body, maxResponseSize)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	// Record response size metric
	if c.metrics != nil {
		c.metrics.RDAPUpstreamResponseSize.WithLabelValues(serverHost).Observe(float64(len(body)))
	}

	// Parse JSON
	if err := json.Unmarshal(body, result); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidResponse, err)
	}

	return nil
}
