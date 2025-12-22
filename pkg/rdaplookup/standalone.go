package rdaplookup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/glimps-re/rdap-lookup/internal/bootstrap"
	"github.com/glimps-re/rdap-lookup/internal/cache"
	"github.com/glimps-re/rdap-lookup/internal/rdap"
	"github.com/glimps-re/rdap-lookup/internal/schema"
)

// Compile-time interface compliance check.
var _ RDAPClient = (*StandaloneClient)(nil)

// Default configuration values for StandaloneClient.
const (
	DefaultStandaloneTimeout    = 10 * time.Second
	DefaultCacheSize            = 50 * 1024 * 1024 // 50MB
	DefaultCacheTTL             = 24 * time.Hour
	DefaultNegativeTTL          = 1 * time.Hour
	DefaultBootstrapRefresh     = 24 * time.Hour
	DefaultStandaloneMaxRetries = 2
	DefaultStandaloneMaxEntries = 10000
	DefaultStandaloneUserAgent  = "rdaplookup-standalone/1.0"
)

// StandaloneClient performs direct RDAP lookups with built-in caching.
// It fetches IANA bootstrap data on first use and refreshes it periodically.
// StandaloneClient implements the RDAPClient interface.
type StandaloneClient struct {
	config standaloneConfig

	// Bootstrap
	bootstrapLoader *bootstrap.Loader
	resolver        *bootstrap.Resolver
	bootstrapOnce   sync.Once
	bootstrapErr    error
	resolverMu      sync.RWMutex

	// RDAP client
	rdapClient *rdap.Client

	// Cache
	cache cache.Cache

	// Configuration
	cacheTTL    time.Duration
	negativeTTL time.Duration

	// Background tasks
	cancelFunc context.CancelFunc
	wg         sync.WaitGroup
	closed     atomic.Bool
	logger     *slog.Logger
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
		config:          cfg,
		bootstrapLoader: bootstrap.NewLoader(cfg.timeout),
		cacheTTL:        cfg.cacheTTL,
		negativeTTL:     cfg.negativeTTL,
		logger:          cfg.logger,
	}

	// Create RDAP client (resolver will be set after bootstrap loads)
	client.rdapClient = rdap.NewClient(
		cfg.timeout,
		rdap.WithMaxRetries(cfg.maxRetries),
		rdap.WithUserAgent(cfg.userAgent),
		rdap.WithLogger(cfg.logger),
	)

	// Initialize cache if enabled
	if cfg.cacheEnabled {
		memCache, err := cache.NewMemoryCache(cache.MemoryCacheConfig{
			MaxEntries: DefaultStandaloneMaxEntries,
			MaxSize:    cfg.cacheSize,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create cache: %w", err)
		}
		client.cache = memCache
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
	cacheKey := cache.BuildKey(cache.KeyPrefixDomain, name)
	if c.cache != nil {
		if entry, err := c.cache.Get(ctx, cacheKey); err == nil {
			if entry.Negative {
				return nil, ErrNotFound
			}
			var resp DomainResponse
			if err := json.Unmarshal(entry.Value, &resp); err == nil {
				resp.Cached = true
				return &resp, nil
			}
		}
	}

	// Query RDAP
	rawResp, err := c.rdapClient.QueryDomain(ctx, name)
	if err != nil {
		if errors.Is(err, rdap.ErrNotFound) {
			if c.cache != nil {
				_ = c.cache.Set(ctx, cacheKey, nil, c.negativeTTL, true)
			}
			return nil, ErrNotFound
		}
		return nil, err
	}

	// Transform to simplified schema
	simple := schema.TransformDomain(rawResp, c.getRDAPServer(name, "domain"))

	// Convert to public response type
	resp := domainFromSchema(simple)

	// Cache result
	if c.cache != nil {
		if data, err := json.Marshal(resp); err == nil {
			_ = c.cache.Set(ctx, cacheKey, data, c.cacheTTL, false)
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
	cacheKey := cache.BuildKey(cache.KeyPrefixIP, addr)
	if c.cache != nil {
		if entry, err := c.cache.Get(ctx, cacheKey); err == nil {
			if entry.Negative {
				return nil, ErrNotFound
			}
			var resp IPResponse
			if err := json.Unmarshal(entry.Value, &resp); err == nil {
				resp.Cached = true
				return &resp, nil
			}
		}
	}

	// Query RDAP
	rawResp, err := c.rdapClient.QueryIP(ctx, addr)
	if err != nil {
		if errors.Is(err, rdap.ErrNotFound) {
			if c.cache != nil {
				_ = c.cache.Set(ctx, cacheKey, nil, c.negativeTTL, true)
			}
			return nil, ErrNotFound
		}
		return nil, err
	}

	// Transform to simplified schema
	simple := schema.TransformIP(rawResp, c.getRDAPServer(addr, "ip"))

	// Convert to public response type
	resp := ipFromSchema(simple)

	// Cache result
	if c.cache != nil {
		if data, err := json.Marshal(resp); err == nil {
			_ = c.cache.Set(ctx, cacheKey, data, c.cacheTTL, false)
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
	cacheKey := cache.BuildKey(cache.KeyPrefixASN, fmt.Sprintf("%d", asnNum))
	if c.cache != nil {
		if entry, err := c.cache.Get(ctx, cacheKey); err == nil {
			if entry.Negative {
				return nil, ErrNotFound
			}
			var resp ASNResponse
			if err := json.Unmarshal(entry.Value, &resp); err == nil {
				resp.Cached = true
				return &resp, nil
			}
		}
	}

	// Query RDAP
	rawResp, err := c.rdapClient.QueryASN(ctx, asnNum)
	if err != nil {
		if errors.Is(err, rdap.ErrNotFound) {
			if c.cache != nil {
				_ = c.cache.Set(ctx, cacheKey, nil, c.negativeTTL, true)
			}
			return nil, ErrNotFound
		}
		return nil, err
	}

	// Transform to simplified schema
	simple := schema.TransformASN(rawResp, c.getRDAPServer(fmt.Sprintf("%d", asnNum), "autnum"))

	// Convert to public response type
	resp := asnFromSchema(simple)

	// Cache result
	if c.cache != nil {
		if data, err := json.Marshal(resp); err == nil {
			_ = c.cache.Set(ctx, cacheKey, data, c.cacheTTL, false)
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

	// SSRF Prevention: Validate server URL against IANA bootstrap allowlist
	if err := c.isServerAllowed(serverURL); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrServerNotAllowed, serverURL)
	}

	// Check cache (include server URL in key to avoid collisions)
	cacheKey := cache.BuildKey(cache.KeyPrefixEntity, serverURL+":"+handle)
	if c.cache != nil {
		if entry, err := c.cache.Get(ctx, cacheKey); err == nil {
			if entry.Negative {
				return nil, ErrNotFound
			}
			var resp EntityResponse
			if err := json.Unmarshal(entry.Value, &resp); err == nil {
				resp.Cached = true
				return &resp, nil
			}
		}
	}

	// Query RDAP
	rawResp, err := c.rdapClient.QueryEntity(ctx, handle, serverURL)
	if err != nil {
		if errors.Is(err, rdap.ErrNotFound) {
			if c.cache != nil {
				_ = c.cache.Set(ctx, cacheKey, nil, c.negativeTTL, true)
			}
			return nil, ErrNotFound
		}
		return nil, err
	}

	// Transform to simplified schema
	simple := schema.TransformEntityResponse(rawResp, serverURL)

	// Convert to public response type
	resp := entityFromSchema(simple)

	// Cache result
	if c.cache != nil {
		if data, err := json.Marshal(resp); err == nil {
			_ = c.cache.Set(ctx, cacheKey, data, c.cacheTTL, false)
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
					result.Cached = resp.Cached
				}
			case "ip":
				resp, err := c.LookupIP(ctx, q.Value)
				if err != nil {
					result.Error = err.Error()
				} else {
					result.Data = resp
					result.Cached = resp.Cached
				}
			case "asn":
				resp, err := c.LookupASN(ctx, q.Value)
				if err != nil {
					result.Error = err.Error()
				} else {
					result.Data = resp
					result.Cached = resp.Cached
				}
			case "entity":
				resp, err := c.LookupEntity(ctx, q.Value, q.ServerURL)
				if err != nil {
					result.Error = err.Error()
				} else {
					result.Data = resp
					result.Cached = resp.Cached
				}
			default:
				result.Error = "unsupported query type"
			}

			results[idx] = result
		}(i, query)
	}

	wg.Wait()

	// Calculate stats
	var success, errs, cacheHits int
	for _, r := range results {
		if r.Error != "" {
			errs++
		} else {
			success++
			if r.Cached {
				cacheHits++
			}
		}
	}

	return &BatchResponse{
		Results: results,
		Stats: &BatchStats{
			Total:      len(results),
			Success:    success,
			Errors:     errs,
			CacheHits:  cacheHits,
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

	// Close cache
	if c.cache != nil {
		_ = c.cache.Close()
	}

	return nil
}

// Stats returns cache statistics.
func (c *StandaloneClient) Stats() CacheStats {
	if c.cache == nil {
		return CacheStats{}
	}
	stats := c.cache.Stats()
	return CacheStats{
		Hits:      stats.Hits,
		Misses:    stats.Misses,
		Entries:   stats.Entries,
		SizeBytes: stats.SizeBytes,
		Evictions: stats.Evictions,
		HitRate:   stats.HitRate,
	}
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

// IsReady returns true if bootstrap data has been loaded.
func (c *StandaloneClient) IsReady() bool {
	c.resolverMu.RLock()
	defer c.resolverMu.RUnlock()
	return c.resolver != nil
}

// ensureBootstrap ensures bootstrap data is loaded.
func (c *StandaloneClient) ensureBootstrap(ctx context.Context) error {
	c.bootstrapOnce.Do(func() {
		c.bootstrapErr = c.loadBootstrap(ctx)
	})
	return c.bootstrapErr
}

// loadBootstrap loads the IANA bootstrap data.
func (c *StandaloneClient) loadBootstrap(ctx context.Context) error {
	bootstrapData, err := c.bootstrapLoader.LoadAll(ctx)
	if err != nil {
		return fmt.Errorf("failed to load bootstrap data: %w", err)
	}

	resolver := bootstrap.NewResolver(bootstrapData)

	c.resolverMu.Lock()
	c.resolver = resolver
	c.resolverMu.Unlock()

	// Update RDAP client with the resolver
	c.rdapClient.SetResolver(resolver)

	c.logger.Info("bootstrap data loaded",
		slog.Int("tlds", bootstrapData.DNS.TLDCount()),
		slog.Int("ipv4_prefixes", bootstrapData.IPv4.PrefixCount()),
		slog.Int("ipv6_prefixes", bootstrapData.IPv6.PrefixCount()),
		slog.Int("asn_ranges", bootstrapData.ASN.RangeCount()),
	)

	return nil
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
			refreshCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
			bootstrapData, err := c.bootstrapLoader.LoadAll(refreshCtx)
			cancel()

			if err != nil {
				c.logger.Warn("failed to refresh bootstrap data",
					slog.String("error", err.Error()),
				)
				continue
			}

			resolver := bootstrap.NewResolver(bootstrapData)

			c.resolverMu.Lock()
			c.resolver = resolver
			c.resolverMu.Unlock()

			c.rdapClient.SetResolver(resolver)

			c.logger.Debug("bootstrap data refreshed")
		}
	}
}

// getRDAPServer returns the RDAP server URL for the query.
func (c *StandaloneClient) getRDAPServer(query, queryType string) string {
	c.resolverMu.RLock()
	resolver := c.resolver
	c.resolverMu.RUnlock()

	if resolver == nil {
		return ""
	}

	var urls []string
	var err error

	switch queryType {
	case "domain":
		urls, err = resolver.ResolveDomain(query)
	case "ip":
		urls, err = resolver.ResolveIP(query)
	case "autnum":
		if asn, parseErr := parseASN(query); parseErr == nil {
			urls, err = resolver.ResolveASN(asn)
		}
	}

	if err != nil || len(urls) == 0 {
		return ""
	}

	return urls[0]
}

// isServerAllowed checks if a server URL is in the IANA bootstrap allowlist.
func (c *StandaloneClient) isServerAllowed(serverURL string) error {
	c.resolverMu.RLock()
	resolver := c.resolver
	c.resolverMu.RUnlock()

	if resolver == nil {
		return errors.New("bootstrap data not loaded")
	}

	// Get all allowed servers and check if this one is in the list
	allowedServers := resolver.GetAllRDAPServers()
	normalizedURL := normalizeServerURL(serverURL)

	for _, allowed := range allowedServers {
		if normalizeServerURL(allowed) == normalizedURL {
			return nil
		}
	}

	return errors.New("server not in allowlist")
}

// normalizeServerURL normalizes a server URL for comparison.
func normalizeServerURL(serverURL string) string {
	serverURL = strings.TrimSpace(serverURL)
	serverURL = strings.ToLower(serverURL)
	serverURL = strings.TrimSuffix(serverURL, "/")
	return serverURL
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
