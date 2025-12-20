package rdaplookup

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

// Compile-time interface compliance check.
var _ RDAPClient = (*StandaloneClient)(nil)

// Default configuration values for StandaloneClient.
const (
	DefaultStandaloneTimeout     = 10 * time.Second
	DefaultCacheSize             = 50 * 1024 * 1024 // 50MB
	DefaultCacheTTL              = 24 * time.Hour
	DefaultNegativeTTL           = 1 * time.Hour
	DefaultBootstrapRefresh      = 24 * time.Hour
	DefaultStandaloneMaxRetries  = 2
	DefaultStandaloneMaxEntries  = 10000
	DefaultMaxStandaloneRespSize = 10 * 1024 * 1024 // 10MB
	DefaultStandaloneUserAgent   = "rdaplookup-standalone/1.0"
)

// StandaloneClient performs direct RDAP lookups with built-in caching.
// It fetches IANA bootstrap data on first use and refreshes it periodically.
// StandaloneClient implements the RDAPClient interface.
type StandaloneClient struct {
	config standaloneConfig

	// Bootstrap data
	bootstrap     *bootstrapData
	bootstrapOnce sync.Once
	bootstrapErr  error

	// Cache
	cache *standaloneCache

	// HTTP client
	httpClient *http.Client

	// Background tasks
	cancelFunc context.CancelFunc
	wg         sync.WaitGroup
	closed     atomic.Bool
}

// standaloneConfig holds configuration for StandaloneClient.
type standaloneConfig struct {
	timeout          time.Duration
	cacheSize        int64
	cacheTTL         time.Duration
	negativeTTL      time.Duration
	bootstrapRefresh time.Duration
	maxRetries       int
	userAgent        string
	normalizeDomains bool
	cacheEnabled     bool
	logger           *slog.Logger
}

// StandaloneOption configures the StandaloneClient.
type StandaloneOption func(*standaloneConfig)

// WithStandaloneTimeout sets the HTTP request timeout for the standalone client.
func WithStandaloneTimeout(d time.Duration) StandaloneOption {
	return func(c *standaloneConfig) {
		c.timeout = d
	}
}

// WithCacheSize sets the maximum RAM cache size in bytes.
func WithCacheSize(bytes int64) StandaloneOption {
	return func(c *standaloneConfig) {
		c.cacheSize = bytes
	}
}

// WithCacheTTL sets the TTL for cached positive responses.
func WithCacheTTL(d time.Duration) StandaloneOption {
	return func(c *standaloneConfig) {
		c.cacheTTL = d
	}
}

// WithNegativeTTL sets the TTL for cached negative (not found) responses.
func WithNegativeTTL(d time.Duration) StandaloneOption {
	return func(c *standaloneConfig) {
		c.negativeTTL = d
	}
}

// WithBootstrapRefresh sets the interval for refreshing IANA bootstrap data.
func WithBootstrapRefresh(d time.Duration) StandaloneOption {
	return func(c *standaloneConfig) {
		c.bootstrapRefresh = d
	}
}

// WithStandaloneMaxRetries sets the maximum number of retries for failed requests.
func WithStandaloneMaxRetries(n int) StandaloneOption {
	return func(c *standaloneConfig) {
		c.maxRetries = n
	}
}

// WithStandaloneUserAgent sets the User-Agent header for HTTP requests.
func WithStandaloneUserAgent(ua string) StandaloneOption {
	return func(c *standaloneConfig) {
		c.userAgent = ua
	}
}

// WithStandaloneDomainNormalization enables or disables automatic domain normalization.
// When enabled (default), subdomains like "www.example.com" are normalized
// to the registrable domain "example.com" before lookup.
func WithStandaloneDomainNormalization(enabled bool) StandaloneOption {
	return func(c *standaloneConfig) {
		c.normalizeDomains = enabled
	}
}

// WithoutCache disables caching entirely.
func WithoutCache() StandaloneOption {
	return func(c *standaloneConfig) {
		c.cacheEnabled = false
	}
}

// WithStandaloneLogger sets a custom logger.
func WithStandaloneLogger(logger *slog.Logger) StandaloneOption {
	return func(c *standaloneConfig) {
		c.logger = logger
	}
}

// NewStandaloneClient creates a new standalone RDAP client with built-in caching.
// It fetches IANA bootstrap data on first use and refreshes it periodically.
func NewStandaloneClient(opts ...StandaloneOption) (*StandaloneClient, error) {
	cfg := standaloneConfig{
		timeout:          DefaultStandaloneTimeout,
		cacheSize:        DefaultCacheSize,
		cacheTTL:         DefaultCacheTTL,
		negativeTTL:      DefaultNegativeTTL,
		bootstrapRefresh: DefaultBootstrapRefresh,
		maxRetries:       DefaultStandaloneMaxRetries,
		userAgent:        DefaultStandaloneUserAgent,
		normalizeDomains: true,
		cacheEnabled:     true,
		logger:           slog.Default(),
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	client := &StandaloneClient{
		config:    cfg,
		bootstrap: newBootstrapData(),
		httpClient: &http.Client{
			Timeout: cfg.timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}

	// Initialize cache if enabled
	if cfg.cacheEnabled {
		cache, err := newStandaloneCache(cfg.cacheSize)
		if err != nil {
			return nil, fmt.Errorf("failed to create cache: %w", err)
		}
		client.cache = cache
	}

	// Start background refresh
	ctx, cancel := context.WithCancel(context.Background())
	client.cancelFunc = cancel
	client.wg.Add(1)
	go client.backgroundRefresh(ctx)

	return client, nil
}

// LookupDomain performs a domain lookup.
// If domain normalization is enabled (default), subdomains are automatically
// reduced to the registrable domain (e.g., "www.example.com" -> "example.com").
func (c *StandaloneClient) LookupDomain(ctx context.Context, name string) (*DomainResponse, error) {
	if c.closed.Load() {
		return nil, errors.New("client is closed")
	}

	// Ensure bootstrap is loaded
	if err := c.ensureBootstrap(ctx); err != nil {
		return nil, fmt.Errorf("bootstrap initialization failed: %w", err)
	}

	// Normalize domain if enabled
	if c.config.normalizeDomains {
		name = NormalizeDomain(name)
	}

	if name == "" {
		return nil, errors.New("invalid domain name")
	}

	name = strings.ToLower(strings.TrimSuffix(name, "."))

	// Check cache
	cacheKey := "domain:" + name
	if c.cache != nil {
		if entry, ok := c.cache.get(cacheKey); ok {
			if entry.negative {
				return nil, ErrNotFound
			}
			var resp DomainResponse
			if err := json.Unmarshal(entry.value, &resp); err == nil {
				return &resp, nil
			}
		}
	}

	// Resolve RDAP server
	urls, err := c.bootstrap.resolveDomain(name)
	if err != nil {
		return nil, fmt.Errorf("no RDAP server for domain: %w", err)
	}

	// Query RDAP
	path := "domain/" + url.PathEscape(name)
	var rawResp rawDomainResponse
	rdapURL, err := c.queryWithRetry(ctx, urls, path, &rawResp)
	if err != nil {
		if errors.Is(err, errRDAPNotFound) && c.cache != nil {
			// Cache negative result
			c.cache.setNegative(cacheKey, c.config.negativeTTL)
			return nil, ErrNotFound
		}
		return nil, err
	}

	// Transform to simplified response
	resp := transformDomainResponse(&rawResp, rdapURL)

	// Cache result
	if c.cache != nil {
		if data, err := json.Marshal(resp); err == nil {
			c.cache.set(cacheKey, data, c.config.cacheTTL)
		}
	}

	return resp, nil
}

// LookupIP performs an IP address lookup (IPv4 or IPv6).
func (c *StandaloneClient) LookupIP(ctx context.Context, addr string) (*IPResponse, error) {
	if c.closed.Load() {
		return nil, errors.New("client is closed")
	}

	if err := c.ensureBootstrap(ctx); err != nil {
		return nil, fmt.Errorf("bootstrap initialization failed: %w", err)
	}

	if addr == "" {
		return nil, errors.New("invalid IP address")
	}

	// Check cache
	cacheKey := "ip:" + addr
	if c.cache != nil {
		if entry, ok := c.cache.get(cacheKey); ok {
			if entry.negative {
				return nil, ErrNotFound
			}
			var resp IPResponse
			if err := json.Unmarshal(entry.value, &resp); err == nil {
				return &resp, nil
			}
		}
	}

	// Resolve RDAP server
	urls, err := c.bootstrap.resolveIP(addr)
	if err != nil {
		return nil, fmt.Errorf("no RDAP server for IP: %w", err)
	}

	// Query RDAP
	path := "ip/" + url.PathEscape(addr)
	var rawResp rawIPResponse
	rdapURL, err := c.queryWithRetry(ctx, urls, path, &rawResp)
	if err != nil {
		if errors.Is(err, errRDAPNotFound) && c.cache != nil {
			c.cache.setNegative(cacheKey, c.config.negativeTTL)
			return nil, ErrNotFound
		}
		return nil, err
	}

	// Transform to simplified response
	resp := transformIPResponse(&rawResp, rdapURL)

	// Cache result
	if c.cache != nil {
		if data, err := json.Marshal(resp); err == nil {
			c.cache.set(cacheKey, data, c.config.cacheTTL)
		}
	}

	return resp, nil
}

// LookupASN performs an ASN lookup.
// The asn parameter can be a number (15169) or prefixed (AS15169).
func (c *StandaloneClient) LookupASN(ctx context.Context, asn string) (*ASNResponse, error) {
	if c.closed.Load() {
		return nil, errors.New("client is closed")
	}

	if err := c.ensureBootstrap(ctx); err != nil {
		return nil, fmt.Errorf("bootstrap initialization failed: %w", err)
	}

	// Parse ASN
	asnNum, err := parseASN(asn)
	if err != nil {
		return nil, fmt.Errorf("invalid ASN: %w", err)
	}

	// Check cache
	cacheKey := fmt.Sprintf("asn:%d", asnNum)
	if c.cache != nil {
		if entry, ok := c.cache.get(cacheKey); ok {
			if entry.negative {
				return nil, ErrNotFound
			}
			var resp ASNResponse
			if err := json.Unmarshal(entry.value, &resp); err == nil {
				return &resp, nil
			}
		}
	}

	// Resolve RDAP server
	urls, err := c.bootstrap.resolveASN(asnNum)
	if err != nil {
		return nil, fmt.Errorf("no RDAP server for ASN: %w", err)
	}

	// Query RDAP
	path := fmt.Sprintf("autnum/%d", asnNum)
	var rawResp rawASNResponse
	rdapURL, err := c.queryWithRetry(ctx, urls, path, &rawResp)
	if err != nil {
		if errors.Is(err, errRDAPNotFound) && c.cache != nil {
			c.cache.setNegative(cacheKey, c.config.negativeTTL)
			return nil, ErrNotFound
		}
		return nil, err
	}

	// Transform to simplified response
	resp := transformASNResponse(&rawResp, rdapURL)

	// Cache result
	if c.cache != nil {
		if data, err := json.Marshal(resp); err == nil {
			c.cache.set(cacheKey, data, c.config.cacheTTL)
		}
	}

	return resp, nil
}

// ErrServerNotAllowed is returned when a server URL is not in the IANA bootstrap allowlist.
var ErrServerNotAllowed = errors.New("server URL not in allowed list")

// LookupEntity performs an entity lookup by handle.
// Requires the RDAP server URL where the entity is registered.
// The server URL must be in the IANA bootstrap allowlist to prevent SSRF attacks.
func (c *StandaloneClient) LookupEntity(ctx context.Context, handle, serverURL string) (*EntityResponse, error) {
	if c.closed.Load() {
		return nil, errors.New("client is closed")
	}

	// Ensure bootstrap is loaded for server validation
	if err := c.ensureBootstrap(ctx); err != nil {
		return nil, fmt.Errorf("bootstrap initialization failed: %w", err)
	}

	if handle == "" {
		return nil, errors.New("invalid entity handle")
	}
	if serverURL == "" {
		return nil, errors.New("server URL required for entity lookup")
	}

	// Validate server URL format
	if _, err := url.Parse(serverURL); err != nil {
		return nil, fmt.Errorf("invalid server URL: %w", err)
	}

	// SSRF Prevention: Validate server URL against IANA bootstrap allowlist
	if err := c.bootstrap.isServerAllowed(serverURL); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrServerNotAllowed, serverURL)
	}

	// Check cache (include server URL in key to avoid collisions)
	cacheKey := "entity:" + serverURL + ":" + handle
	if c.cache != nil {
		if entry, ok := c.cache.get(cacheKey); ok {
			if entry.negative {
				return nil, ErrNotFound
			}
			var resp EntityResponse
			if err := json.Unmarshal(entry.value, &resp); err == nil {
				return &resp, nil
			}
		}
	}

	// Query RDAP
	path := "entity/" + url.PathEscape(handle)
	var rawResp rawEntityResponse
	rdapURL, err := c.queryWithRetry(ctx, []string{serverURL}, path, &rawResp)
	if err != nil {
		if errors.Is(err, errRDAPNotFound) && c.cache != nil {
			c.cache.setNegative(cacheKey, c.config.negativeTTL)
			return nil, ErrNotFound
		}
		return nil, err
	}

	// Transform to simplified response
	resp := transformEntityResponse(&rawResp, rdapURL)

	// Cache result
	if c.cache != nil {
		if data, err := json.Marshal(resp); err == nil {
			c.cache.set(cacheKey, data, c.config.cacheTTL)
		}
	}

	return resp, nil
}

// BatchLookup performs a batch lookup of multiple queries.
func (c *StandaloneClient) BatchLookup(ctx context.Context, req *BatchRequest) (*BatchResponse, error) {
	if c.closed.Load() {
		return nil, errors.New("client is closed")
	}

	if req == nil || len(req.Queries) == 0 {
		return &BatchResponse{
			Stats: &BatchStats{Total: 0},
		}, nil
	}

	start := time.Now()
	results := make([]BatchResult, len(req.Queries))

	// Process queries concurrently with bounded parallelism
	const maxConcurrency = 10
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup

	for i, query := range req.Queries {
		wg.Add(1)
		go func(idx int, q BatchQuery) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result := BatchResult{
				Type:  q.Type,
				Value: q.Value,
			}

			switch q.Type {
			case "domain":
				resp, err := c.LookupDomain(ctx, q.Value)
				if err != nil {
					result.Error = err.Error()
				} else {
					result.Data = resp
				}
			case "ip":
				resp, err := c.LookupIP(ctx, q.Value)
				if err != nil {
					result.Error = err.Error()
				} else {
					result.Data = resp
				}
			case "asn":
				resp, err := c.LookupASN(ctx, q.Value)
				if err != nil {
					result.Error = err.Error()
				} else {
					result.Data = resp
				}
			case "entity":
				resp, err := c.LookupEntity(ctx, q.Value, q.ServerURL)
				if err != nil {
					result.Error = err.Error()
				} else {
					result.Data = resp
				}
			default:
				result.Error = "unsupported query type"
			}

			results[idx] = result
		}(i, query)
	}

	wg.Wait()

	// Calculate stats
	var success, errs int
	for _, r := range results {
		if r.Error != "" {
			errs++
		} else {
			success++
		}
	}

	return &BatchResponse{
		Results: results,
		Stats: &BatchStats{
			Total:      len(results),
			Success:    success,
			Errors:     errs,
			DurationMs: time.Since(start).Milliseconds(),
		},
	}, nil
}

// Close releases resources. Safe to call multiple times.
func (c *StandaloneClient) Close() error {
	if c.closed.Swap(true) {
		return nil // Already closed
	}

	// Stop background tasks
	if c.cancelFunc != nil {
		c.cancelFunc()
	}
	c.wg.Wait()

	// Clear cache
	if c.cache != nil {
		c.cache.clear()
	}

	return nil
}

// Stats returns cache statistics.
func (c *StandaloneClient) Stats() CacheStats {
	if c.cache == nil {
		return CacheStats{}
	}
	return c.cache.stats()
}

// IsReady returns true if bootstrap data has been loaded.
func (c *StandaloneClient) IsReady() bool {
	return c.bootstrap.isLoaded()
}

// ensureBootstrap ensures bootstrap data is loaded.
func (c *StandaloneClient) ensureBootstrap(ctx context.Context) error {
	c.bootstrapOnce.Do(func() {
		c.bootstrapErr = c.bootstrap.load(ctx, c.httpClient, c.config.logger)
	})
	return c.bootstrapErr
}

// backgroundRefresh periodically refreshes bootstrap data.
func (c *StandaloneClient) backgroundRefresh(ctx context.Context) {
	defer c.wg.Done()

	ticker := time.NewTicker(c.config.bootstrapRefresh)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.bootstrap.load(ctx, c.httpClient, c.config.logger); err != nil {
				c.config.logger.Warn("failed to refresh bootstrap data",
					slog.String("error", err.Error()),
				)
			}
		}
	}
}

// queryWithRetry attempts to query RDAP servers with retry logic.
func (c *StandaloneClient) queryWithRetry(ctx context.Context, serverURLs []string, path string, result any) (string, error) {
	var lastErr error

	for _, baseURL := range serverURLs {
		if !strings.HasSuffix(baseURL, "/") {
			baseURL += "/"
		}

		fullURL := baseURL + path

		for attempt := 0; attempt <= c.config.maxRetries; attempt++ {
			if attempt > 0 {
				backoff := calculateStandaloneBackoff(attempt)
				select {
				case <-ctx.Done():
					return "", ctx.Err()
				case <-time.After(backoff):
				}
			}

			err := c.doQuery(ctx, fullURL, result)
			if err == nil {
				return baseURL, nil
			}

			lastErr = err

			// Don't retry on certain errors
			if errors.Is(err, errRDAPNotFound) ||
				errors.Is(err, context.Canceled) ||
				errors.Is(err, context.DeadlineExceeded) {
				return "", err
			}
		}
	}

	if lastErr != nil {
		return "", lastErr
	}
	return "", errors.New("all RDAP servers failed")
}

// doQuery performs a single RDAP query.
func (c *StandaloneClient) doQuery(ctx context.Context, queryURL string, result any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, queryURL, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", c.config.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return ErrTimeout
		}
		return fmt.Errorf("http request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		// Success
	case http.StatusNotFound:
		return errRDAPNotFound
	case http.StatusTooManyRequests:
		return ErrRateLimited
	default:
		if resp.StatusCode >= 500 {
			return fmt.Errorf("server error: status %d", resp.StatusCode)
		}
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	// Read response with size limit
	limitedReader := io.LimitReader(resp.Body, DefaultMaxStandaloneRespSize)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if err := json.Unmarshal(body, result); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	return nil
}

// Internal error for not found
var errRDAPNotFound = errors.New("object not found in RDAP")

// calculateStandaloneBackoff returns backoff duration for retry.
func calculateStandaloneBackoff(attempt int) time.Duration {
	backoffs := []time.Duration{
		100 * time.Millisecond,
		200 * time.Millisecond,
		400 * time.Millisecond,
		800 * time.Millisecond,
	}
	if attempt <= 0 {
		return backoffs[0]
	}
	if attempt >= len(backoffs) {
		return backoffs[len(backoffs)-1]
	}
	return backoffs[attempt-1]
}

// parseASN parses an ASN string to uint32.
func parseASN(s string) (uint32, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.ToUpper(s), "AS")
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, errors.New("ASN cannot be zero")
	}
	return uint32(n), nil
}

// CacheStats represents cache statistics.
type CacheStats struct {
	Hits      uint64  `json:"hits"`
	Misses    uint64  `json:"misses"`
	Entries   int     `json:"entries"`
	SizeBytes int64   `json:"size_bytes"`
	Evictions uint64  `json:"evictions"`
	HitRate   float64 `json:"hit_rate"`
}

// standaloneCache is an LRU cache with TTL support.
type standaloneCache struct {
	cache     *lru.Cache[string, *cacheEntry]
	maxSize   int64
	sizeBytes atomic.Int64
	hits      atomic.Uint64
	misses    atomic.Uint64
	evictions atomic.Uint64
	mu        sync.RWMutex
}

type cacheEntry struct {
	value     []byte
	expiresAt time.Time
	negative  bool
}

func newStandaloneCache(maxSize int64) (*standaloneCache, error) {
	sc := &standaloneCache{
		maxSize: maxSize,
	}

	cache, err := lru.NewWithEvict[string, *cacheEntry](DefaultStandaloneMaxEntries, sc.onEvict)
	if err != nil {
		return nil, err
	}
	sc.cache = cache

	return sc, nil
}

func (c *standaloneCache) onEvict(_ string, entry *cacheEntry) {
	if entry != nil {
		c.sizeBytes.Add(-int64(len(entry.value)))
		c.evictions.Add(1)
	}
}

func (c *standaloneCache) get(key string) (*cacheEntry, bool) {
	c.mu.RLock()
	entry, ok := c.cache.Get(key)
	c.mu.RUnlock()

	if !ok {
		c.misses.Add(1)
		return nil, false
	}

	if time.Now().After(entry.expiresAt) {
		c.mu.Lock()
		c.cache.Remove(key)
		c.sizeBytes.Add(-int64(len(entry.value)))
		c.mu.Unlock()
		c.misses.Add(1)
		return nil, false
	}

	c.hits.Add(1)
	return entry, true
}

func (c *standaloneCache) set(key string, value []byte, ttl time.Duration) {
	entry := &cacheEntry{
		value:     value,
		expiresAt: time.Now().Add(ttl),
		negative:  false,
	}

	entrySize := int64(len(value))

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.maxSize > 0 {
		if old, ok := c.cache.Peek(key); ok {
			c.sizeBytes.Add(-int64(len(old.value)))
		}

		for c.sizeBytes.Load()+entrySize > c.maxSize && c.cache.Len() > 0 {
			c.cache.RemoveOldest()
		}
	}

	c.cache.Add(key, entry)
	c.sizeBytes.Add(entrySize)
}

func (c *standaloneCache) setNegative(key string, ttl time.Duration) {
	entry := &cacheEntry{
		value:     nil,
		expiresAt: time.Now().Add(ttl),
		negative:  true,
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache.Add(key, entry)
}

func (c *standaloneCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache.Purge()
	c.sizeBytes.Store(0)
}

func (c *standaloneCache) stats() CacheStats {
	hits := c.hits.Load()
	misses := c.misses.Load()
	total := hits + misses

	var hitRate float64
	if total > 0 {
		hitRate = float64(hits) / float64(total)
	}

	c.mu.RLock()
	entries := c.cache.Len()
	c.mu.RUnlock()

	return CacheStats{
		Hits:      hits,
		Misses:    misses,
		Entries:   entries,
		SizeBytes: c.sizeBytes.Load(),
		Evictions: c.evictions.Load(),
		HitRate:   hitRate,
	}
}

// bootstrapData holds IANA bootstrap information.
type bootstrapData struct {
	dns struct {
		tldToURLs map[string][]string
	}
	ipv4 struct {
		prefixes []ipv4Entry
	}
	ipv6 struct {
		prefixes []ipv6Entry
	}
	asn struct {
		ranges []asnEntry
	}
	// allowedServers contains normalized hostnames from all bootstrap data
	// for SSRF prevention in entity lookups.
	allowedServers map[string]struct{}
	loaded         atomic.Bool
	mu             sync.RWMutex
}

type ipv4Entry struct {
	prefix netip.Prefix
	urls   []string
}

type ipv6Entry struct {
	prefix netip.Prefix
	urls   []string
}

type asnEntry struct {
	start uint32
	end   uint32
	urls  []string
}

func newBootstrapData() *bootstrapData {
	return &bootstrapData{
		allowedServers: make(map[string]struct{}),
	}
}

func (b *bootstrapData) isLoaded() bool {
	return b.loaded.Load()
}

func (b *bootstrapData) resolveDomain(domain string) ([]string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(b.dns.tldToURLs) == 0 {
		return nil, errors.New("bootstrap data not loaded")
	}

	// Extract TLD
	tld := extractTLD(domain)
	if tld == "" {
		return nil, errors.New("invalid domain")
	}

	urls, ok := b.dns.tldToURLs[strings.ToLower(tld)]
	if !ok {
		return nil, fmt.Errorf("no RDAP server for TLD: %s", tld)
	}

	return urls, nil
}

func (b *bootstrapData) resolveIP(addrStr string) ([]string, error) {
	addr, err := netip.ParseAddr(addrStr)
	if err != nil {
		return nil, fmt.Errorf("invalid IP address: %w", err)
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if addr.Is4() {
		if len(b.ipv4.prefixes) == 0 {
			return nil, errors.New("IPv4 bootstrap data not loaded")
		}

		var bestMatch *ipv4Entry
		var bestBits int

		for i := range b.ipv4.prefixes {
			entry := &b.ipv4.prefixes[i]
			if entry.prefix.Contains(addr) {
				bits := entry.prefix.Bits()
				if bestMatch == nil || bits > bestBits {
					bestMatch = entry
					bestBits = bits
				}
			}
		}

		if bestMatch == nil {
			return nil, fmt.Errorf("no RDAP server for IP: %s", addrStr)
		}
		return bestMatch.urls, nil
	}

	// IPv6
	if len(b.ipv6.prefixes) == 0 {
		return nil, errors.New("IPv6 bootstrap data not loaded")
	}

	var bestMatch *ipv6Entry
	var bestBits int

	for i := range b.ipv6.prefixes {
		entry := &b.ipv6.prefixes[i]
		if entry.prefix.Contains(addr) {
			bits := entry.prefix.Bits()
			if bestMatch == nil || bits > bestBits {
				bestMatch = entry
				bestBits = bits
			}
		}
	}

	if bestMatch == nil {
		return nil, fmt.Errorf("no RDAP server for IP: %s", addrStr)
	}
	return bestMatch.urls, nil
}

func (b *bootstrapData) resolveASN(asn uint32) ([]string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(b.asn.ranges) == 0 {
		return nil, errors.New("ASN bootstrap data not loaded")
	}

	for i := range b.asn.ranges {
		entry := &b.asn.ranges[i]
		if asn >= entry.start && asn <= entry.end {
			return entry.urls, nil
		}
	}

	return nil, fmt.Errorf("no RDAP server for ASN: %d", asn)
}

// isServerAllowed checks if a server URL is in the IANA bootstrap allowlist.
// This prevents SSRF attacks by ensuring only known RDAP servers can be queried.
func (b *bootstrapData) isServerAllowed(serverURL string) error {
	if serverURL == "" {
		return errors.New("empty server URL")
	}

	normalized, err := normalizeServerHost(serverURL)
	if err != nil {
		return err
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(b.allowedServers) == 0 {
		return errors.New("bootstrap data not loaded")
	}

	if _, ok := b.allowedServers[normalized]; !ok {
		return errors.New("server not in allowlist")
	}

	return nil
}

// normalizeServerHost extracts and normalizes the host from a server URL.
func normalizeServerHost(serverURL string) (string, error) {
	// Ensure URL has a scheme for proper parsing
	urlToParse := serverURL
	if !strings.HasPrefix(urlToParse, "http://") && !strings.HasPrefix(urlToParse, "https://") {
		urlToParse = "https://" + urlToParse
	}

	parsed, err := url.Parse(urlToParse)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	host := strings.ToLower(parsed.Host)
	if host == "" {
		return "", errors.New("empty host in URL")
	}

	// Remove default ports
	host = strings.TrimSuffix(host, ":443")
	host = strings.TrimSuffix(host, ":80")

	return host, nil
}

func extractTLD(domain string) string {
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return ""
	}

	lastDot := strings.LastIndex(domain, ".")
	if lastDot == -1 {
		return domain
	}

	return domain[lastDot+1:]
}
