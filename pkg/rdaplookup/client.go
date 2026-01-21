package rdaplookup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultTimeout is the default request timeout.
	DefaultTimeout = 30 * time.Second

	// DefaultMaxRetries is the default number of retries.
	DefaultMaxRetries = 2

	// DefaultMaxResponseSize is the maximum response size (10MB).
	DefaultMaxResponseSize = 10 * 1024 * 1024

	// apiV1Prefix is the prefix for API v1 endpoints.
	apiV1Prefix = "/api/v1"
)

// Client is the rdap-lookup API client.
type Client struct {
	baseURL          string
	httpClient       *http.Client
	maxRetries       int
	maxResponseSize  int64
	userAgent        string
	normalizeDomains bool // Extract registrable domain from subdomains (default: true)
}

// Option configures the Client.
type Option func(*Client)

// NewClient creates a new rdap-lookup API client.
func NewClient(baseURL string, opts ...Option) (*Client, error) {
	// Validate and normalize base URL
	baseURL = strings.TrimRight(baseURL, "/")
	if _, err := url.Parse(baseURL); err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	c := &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		maxRetries:       DefaultMaxRetries,
		maxResponseSize:  DefaultMaxResponseSize,
		userAgent:        "rdaplookup-client/1.0",
		normalizeDomains: true, // Enabled by default
	}

	for _, opt := range opts {
		opt(c)
	}

	return c, nil
}

// WithTimeout sets the HTTP client timeout.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		c.httpClient.Timeout = d
	}
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) Option {
	return func(c *Client) {
		c.httpClient = client
	}
}

// WithMaxRetries sets the maximum number of retries.
func WithMaxRetries(n int) Option {
	return func(c *Client) {
		c.maxRetries = n
	}
}

// WithUserAgent sets the User-Agent header.
func WithUserAgent(ua string) Option {
	return func(c *Client) {
		c.userAgent = ua
	}
}

// WithMaxResponseSize sets the maximum response size in bytes.
func WithMaxResponseSize(size int64) Option {
	return func(c *Client) {
		c.maxResponseSize = size
	}
}

// WithDomainNormalization enables or disables domain name normalization.
// When enabled (default), subdomain inputs like "www.example.com" are
// normalized to the registrable domain "example.com" before lookup.
func WithDomainNormalization(enabled bool) Option {
	return func(c *Client) {
		c.normalizeDomains = enabled
	}
}

// LookupDomain performs a domain lookup.
// If domain normalization is enabled (default), subdomains are automatically
// reduced to the registrable domain (e.g., "www.example.com" -> "example.com").
func (c *Client) LookupDomain(ctx context.Context, name string) (*DomainResponse, error) {
	// Normalize domain if enabled
	if c.normalizeDomains {
		name = NormalizeDomain(name)
	}

	var resp DomainResponse
	if err := c.doRequest(ctx, "GET", apiV1Prefix+"/domain/"+url.PathEscape(name), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// LookupIP performs an IP address lookup.
func (c *Client) LookupIP(ctx context.Context, addr string) (*IPResponse, error) {
	var resp IPResponse
	if err := c.doRequest(ctx, "GET", apiV1Prefix+"/ip/"+url.PathEscape(addr), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// LookupASN performs an ASN lookup.
func (c *Client) LookupASN(ctx context.Context, asn string) (*ASNResponse, error) {
	var resp ASNResponse
	if err := c.doRequest(ctx, "GET", apiV1Prefix+"/asn/"+url.PathEscape(asn), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// LookupEntity performs an entity lookup.
func (c *Client) LookupEntity(ctx context.Context, handle, serverURL string) (*EntityResponse, error) {
	path := apiV1Prefix + "/entity/" + url.PathEscape(handle)
	if serverURL != "" {
		path += "?server=" + url.QueryEscape(serverURL)
	}
	var resp EntityResponse
	if err := c.doRequest(ctx, "GET", path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// BatchLookup performs a batch lookup of multiple queries.
// If domain normalization is enabled (default), domain queries have their
// values normalized to the registrable domain.
func (c *Client) BatchLookup(ctx context.Context, req *BatchRequest) (*BatchResponse, error) {
	// Normalize domain queries if enabled
	normalizedReq := req
	if c.normalizeDomains {
		normalizedReq = &BatchRequest{
			Queries: make([]BatchQuery, len(req.Queries)),
		}
		copy(normalizedReq.Queries, req.Queries)
		for i := range normalizedReq.Queries {
			if normalizedReq.Queries[i].Type == "domain" {
				normalizedReq.Queries[i].Value = NormalizeDomain(normalizedReq.Queries[i].Value)
			}
		}
	}

	var resp BatchResponse
	if err := c.doRequest(ctx, "POST", apiV1Prefix+"/batch", normalizedReq, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Health checks if the server is healthy.
func (c *Client) Health(ctx context.Context) error {
	return c.doRequest(ctx, "GET", "/healthz", nil, nil)
}

// Ready checks if the server is ready.
func (c *Client) Ready(ctx context.Context) error {
	return c.doRequest(ctx, "GET", "/ready", nil, nil)
}

// Meta returns server metadata.
func (c *Client) Meta(ctx context.Context) (*MetaResponse, error) {
	var resp MetaResponse
	if err := c.doRequest(ctx, "GET", "/meta", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Close releases resources. For the REST API Client, this is a no-op.
// This method exists to satisfy the RDAPClient interface.
func (c *Client) Close() error {
	return nil
}

func (c *Client) doRequest(ctx context.Context, method, path string, body, result any) error {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: 100ms, 200ms, 400ms...
			backoff := time.Duration(100<<(attempt-1)) * time.Millisecond
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}

		err := c.doSingleRequest(ctx, method, path, bodyReader, result)
		if err == nil {
			return nil
		}

		lastErr = err

		// Don't retry on client errors (4xx)
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode >= 400 && apiErr.StatusCode < 500 {
			return err
		}

		// Reset body reader for retry
		if body != nil {
			data, _ := json.Marshal(body)
			bodyReader = bytes.NewReader(data)
		}
	}

	return lastErr
}

func (c *Client) doSingleRequest(ctx context.Context, method, path string, body io.Reader, result any) error {
	fullURL := c.baseURL + path

	req, err := http.NewRequestWithContext(ctx, method, fullURL, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Limit response size
	limitedReader := io.LimitReader(resp.Body, c.maxResponseSize)

	// Read response body
	respBody, err := io.ReadAll(limitedReader)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Check for errors
	if resp.StatusCode >= 400 {
		apiErr := &APIError{
			StatusCode: resp.StatusCode,
			Message:    string(respBody),
		}

		// Try to parse error response
		var errResp ErrorResponse
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != nil {
			apiErr.Code = errResp.Error.Code
			apiErr.Message = errResp.Error.Message
		}

		return apiErr
	}

	// Parse successful response
	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
	}

	return nil
}
