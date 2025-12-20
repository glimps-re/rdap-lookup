package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/glimps-re/rdap-lookup/internal/bootstrap"
	"github.com/glimps-re/rdap-lookup/internal/cache"
	"github.com/glimps-re/rdap-lookup/internal/config"
	"github.com/glimps-re/rdap-lookup/internal/metrics"
	"github.com/glimps-re/rdap-lookup/internal/rdap"
	"github.com/glimps-re/rdap-lookup/internal/schema"
	"github.com/glimps-re/rdap-lookup/internal/validate"
)

// Lookup outcome constants for metrics.
const (
	OutcomeSuccess     = "success"
	OutcomeNotFound    = "not_found"
	OutcomeError       = "error"
	OutcomeTimeout     = "timeout"
	OutcomeRateLimited = "rate_limited"
)

// LookupHandler handles RDAP lookup requests.
type LookupHandler struct {
	client          *rdap.Client
	bootstrap       *bootstrap.Service
	cache           *cache.TieredCache
	serverValidator *validate.RDAPServerValidator
	batchConfig     config.BatchConfig
	metrics         *metrics.Metrics
}

// NewLookupHandler creates a new lookup handler.
func NewLookupHandler(client *rdap.Client, bs *bootstrap.Service, c *cache.TieredCache, batchCfg config.BatchConfig, m *metrics.Metrics) *LookupHandler {
	// Initialize the server validator with bootstrap servers
	var servers []string
	if resolver := bs.Resolver(); resolver != nil {
		servers = resolver.GetAllRDAPServers()
	}

	return &LookupHandler{
		client:          client,
		bootstrap:       bs,
		cache:           c,
		serverValidator: validate.NewRDAPServerValidator(servers),
		batchConfig:     batchCfg,
		metrics:         m,
	}
}

// recordLookupMetrics records metrics for a lookup operation.
func (h *LookupHandler) recordLookupMetrics(lookupType string, err error, cached bool) {
	if h.metrics == nil {
		return
	}

	// Record lookup count
	h.metrics.LookupsTotal.WithLabelValues(lookupType).Inc()

	// Determine outcome
	outcome := OutcomeSuccess
	if err != nil {
		switch {
		case errors.Is(err, rdap.ErrNotFound):
			outcome = OutcomeNotFound
		case errors.Is(err, rdap.ErrRateLimited):
			outcome = OutcomeRateLimited
		case errors.Is(err, context.DeadlineExceeded):
			outcome = OutcomeTimeout
		default:
			outcome = OutcomeError
		}
	}
	h.metrics.LookupOutcomes.WithLabelValues(lookupType, outcome).Inc()

	// Record data source (only for successful lookups)
	if err == nil {
		source := "upstream"
		if cached {
			source = "cache" // We can't distinguish L1/L2 at this level
		}
		h.metrics.LookupSource.WithLabelValues(lookupType, source).Inc()
	}
}

// SetResolver updates the RDAP client's resolver with the current bootstrap resolver.
// This should be called whenever bootstrap data is refreshed.
func (h *LookupHandler) SetResolver(r *bootstrap.Resolver) {
	h.client.SetResolver(r)

	// Update the server validator allowlist with new bootstrap servers
	if r != nil {
		h.serverValidator.UpdateAllowlist(r.GetAllRDAPServers())
	}
}

// LookupDomain handles domain lookup requests.
func (h *LookupHandler) LookupDomain(c echo.Context) error {
	name := strings.ToLower(strings.TrimSpace(c.Param("name")))
	if err := validate.ValidateDomain(name); err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: ErrorDetail{
				Code:    "INVALID_REQUEST",
				Message: "Invalid domain name format",
			},
		})
	}

	ctx := c.Request().Context()
	cacheKey := cache.BuildKey(cache.KeyPrefixDomain, name)

	// Try to get from cache or fetch
	data, cached, err := h.cache.GetOrFetchWithNegative(ctx, cacheKey, func() ([]byte, error) {
		// Update resolver before query
		h.client.SetResolver(h.bootstrap.Resolver())

		resp, err := h.client.QueryDomain(ctx, name)
		if err != nil {
			return nil, err
		}

		// Get the RDAP server URL from bootstrap for reference
		rdapServer := ""
		if resolver := h.bootstrap.Resolver(); resolver != nil {
			if urls, resolveErr := resolver.ResolveDomain(name); resolveErr == nil && len(urls) > 0 {
				rdapServer = urls[0]
			}
		}

		result := schema.TransformDomain(resp, rdapServer)
		return json.Marshal(result)
	}, rdap.ErrNotFound)

	h.recordLookupMetrics("domain", err, cached)

	if err != nil {
		return h.handleError(c, err, "domain", name)
	}

	return h.respondWithData(c, data, cached)
}

// LookupIP handles IP lookup requests.
func (h *LookupHandler) LookupIP(c echo.Context) error {
	addr := strings.TrimSpace(c.Param("addr"))
	if err := validate.ValidateIP(addr); err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: ErrorDetail{
				Code:    "INVALID_REQUEST",
				Message: "Invalid IP address format",
			},
		})
	}

	ctx := c.Request().Context()
	cacheKey := cache.BuildKey(cache.KeyPrefixIP, addr)

	data, cached, err := h.cache.GetOrFetchWithNegative(ctx, cacheKey, func() ([]byte, error) {
		// Update resolver before query
		h.client.SetResolver(h.bootstrap.Resolver())

		resp, err := h.client.QueryIP(ctx, addr)
		if err != nil {
			return nil, err
		}

		// Get the RDAP server URL from bootstrap for reference
		rdapServer := ""
		if resolver := h.bootstrap.Resolver(); resolver != nil {
			if urls, resolveErr := resolver.ResolveIP(addr); resolveErr == nil && len(urls) > 0 {
				rdapServer = urls[0]
			}
		}

		result := schema.TransformIP(resp, rdapServer)
		return json.Marshal(result)
	}, rdap.ErrNotFound)

	h.recordLookupMetrics("ip", err, cached)

	if err != nil {
		return h.handleError(c, err, "ip", addr)
	}

	return h.respondWithData(c, data, cached)
}

// LookupASN handles ASN lookup requests.
func (h *LookupHandler) LookupASN(c echo.Context) error {
	asnStr := strings.TrimSpace(c.Param("asn"))
	if asnStr == "" {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: ErrorDetail{
				Code:    "INVALID_REQUEST",
				Message: "ASN is required",
			},
		})
	}

	// Remove "AS" prefix if present
	asnStr = strings.TrimPrefix(strings.ToUpper(asnStr), "AS")

	// Parse ASN number
	asn64, err := strconv.ParseUint(asnStr, 10, 32)
	if err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: ErrorDetail{
				Code:    "INVALID_REQUEST",
				Message: "Invalid ASN format: " + asnStr,
			},
		})
	}
	asn := uint32(asn64)

	ctx := c.Request().Context()
	cacheKey := cache.BuildKey(cache.KeyPrefixASN, asnStr)

	data, cached, fetchErr := h.cache.GetOrFetchWithNegative(ctx, cacheKey, func() ([]byte, error) {
		// Update resolver before query
		h.client.SetResolver(h.bootstrap.Resolver())

		resp, err := h.client.QueryASN(ctx, asn)
		if err != nil {
			return nil, err
		}

		// Get the RDAP server URL from bootstrap for reference
		rdapServer := ""
		if resolver := h.bootstrap.Resolver(); resolver != nil {
			if urls, resolveErr := resolver.ResolveASN(asn); resolveErr == nil && len(urls) > 0 {
				rdapServer = urls[0]
			}
		}

		result := schema.TransformASN(resp, rdapServer)
		return json.Marshal(result)
	}, rdap.ErrNotFound)

	h.recordLookupMetrics("asn", fetchErr, cached)

	if fetchErr != nil {
		return h.handleError(c, fetchErr, "asn", asnStr)
	}

	return h.respondWithData(c, data, cached)
}

// LookupEntity handles entity lookup requests.
func (h *LookupHandler) LookupEntity(c echo.Context) error {
	handle := strings.TrimSpace(c.Param("handle"))
	if handle == "" {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: ErrorDetail{
				Code:    "INVALID_REQUEST",
				Message: "Entity handle is required",
			},
		})
	}

	// Entity lookups require a server URL as query param (not bootstrappable)
	serverURL := c.QueryParam("server")
	if serverURL == "" {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: ErrorDetail{
				Code:    "INVALID_REQUEST",
				Message: "Server URL is required for entity lookups (use ?server=URL)",
			},
		})
	}

	// SSRF Prevention: Validate server URL against allowlist from bootstrap
	if err := h.serverValidator.IsAllowed(serverURL); err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: ErrorDetail{
				Code:    "INVALID_SERVER",
				Message: "Server URL not in allowed list",
			},
		})
	}

	ctx := c.Request().Context()
	// Include server URL in cache key to prevent cache poisoning
	cacheKey := cache.BuildKey(cache.KeyPrefixEntity, serverURL+":"+handle)

	data, cached, err := h.cache.GetOrFetchWithNegative(ctx, cacheKey, func() ([]byte, error) {
		resp, err := h.client.QueryEntity(ctx, handle, serverURL)
		if err != nil {
			return nil, err
		}

		result := schema.TransformEntityResponse(resp, serverURL)
		return json.Marshal(result)
	}, rdap.ErrNotFound)

	h.recordLookupMetrics("entity", err, cached)

	if err != nil {
		return h.handleError(c, err, "entity", handle)
	}

	return h.respondWithData(c, data, cached)
}

// BatchRequest represents a batch lookup request.
type BatchRequest struct {
	Queries []BatchQuery `json:"queries"`
}

// BatchQuery represents a single query in a batch request.
type BatchQuery struct {
	Type   string `json:"type"`
	Value  string `json:"value"`
	Server string `json:"server,omitempty"` // Required for entity queries
}

// BatchResponse represents a batch lookup response.
type BatchResponse struct {
	Results []BatchResult `json:"results"`
	Stats   BatchStats    `json:"stats"`
}

// BatchResult represents a single result in a batch response.
type BatchResult struct {
	Type   string          `json:"type"`
	Value  string          `json:"value"`
	Data   json.RawMessage `json:"data,omitempty"`
	Error  string          `json:"error,omitempty"`
	Cached bool            `json:"cached"`
}

// BatchStats holds batch processing statistics.
type BatchStats struct {
	Total      int   `json:"total"`
	Success    int   `json:"success"`
	Errors     int   `json:"errors"`
	CacheHits  int   `json:"cache_hits"`
	DurationMs int64 `json:"duration_ms"`
}

// LookupBatch handles batch lookup requests.
func (h *LookupHandler) LookupBatch(c echo.Context) error {
	var req BatchRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: ErrorDetail{
				Code:    "INVALID_REQUEST",
				Message: "Invalid request body format",
			},
		})
	}

	if len(req.Queries) == 0 {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: ErrorDetail{
				Code:    "INVALID_REQUEST",
				Message: "At least one query is required",
			},
		})
	}

	if len(req.Queries) > 100 {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: ErrorDetail{
				Code:    "INVALID_REQUEST",
				Message: "Maximum 100 queries per batch",
			},
		})
	}

	start := time.Now()

	// Create a batch-specific context with timeout
	batchCtx, cancel := context.WithTimeout(c.Request().Context(), h.batchConfig.Timeout)
	defer cancel()

	results := make([]BatchResult, len(req.Queries))

	// Use bounded concurrency for parallel processing
	sem := make(chan struct{}, h.batchConfig.Concurrency)
	var wg sync.WaitGroup

	for i, query := range req.Queries {
		wg.Add(1)
		go func(idx int, q BatchQuery) {
			defer wg.Done()

			// Acquire semaphore slot
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-batchCtx.Done():
				results[idx] = BatchResult{
					Type:  q.Type,
					Value: q.Value,
					Error: "batch timeout exceeded",
				}
				return
			}

			// Check context before processing
			if batchCtx.Err() != nil {
				results[idx] = BatchResult{
					Type:  q.Type,
					Value: q.Value,
					Error: "batch timeout exceeded",
				}
				return
			}

			results[idx] = h.processBatchQuery(batchCtx, q)
		}(i, query)
	}

	wg.Wait()

	// Calculate stats
	stats := BatchStats{Total: len(req.Queries)}
	for _, result := range results {
		if result.Error == "" {
			stats.Success++
		} else {
			stats.Errors++
		}
		if result.Cached {
			stats.CacheHits++
		}
	}
	stats.DurationMs = time.Since(start).Milliseconds()

	// Record batch metrics
	if h.metrics != nil {
		h.metrics.BatchRequestsTotal.Inc()
		h.metrics.BatchSizeHistogram.Observe(float64(len(req.Queries)))
	}

	return c.JSON(http.StatusOK, BatchResponse{
		Results: results,
		Stats:   stats,
	})
}

func (h *LookupHandler) processBatchQuery(ctx context.Context, query BatchQuery) BatchResult {
	result := BatchResult{
		Type:  query.Type,
		Value: query.Value,
	}

	var data []byte
	var cached bool
	var err error

	switch strings.ToLower(query.Type) {
	case "domain":
		data, cached, err = h.lookupDomainData(ctx, query.Value)
	case "ip":
		data, cached, err = h.lookupIPData(ctx, query.Value)
	case "asn":
		data, cached, err = h.lookupASNData(ctx, query.Value)
	case "entity":
		if query.Server == "" {
			result.Error = "server URL required for entity queries"
			return result
		}
		// SSRF Prevention: Validate server URL against allowlist
		if validateErr := h.serverValidator.IsAllowed(query.Server); validateErr != nil {
			result.Error = "server URL not in allowed list"
			return result
		}
		data, cached, err = h.lookupEntityData(ctx, query.Value, query.Server)
	default:
		result.Error = "unknown query type"
		return result
	}

	if err != nil {
		// Sanitize error messages to avoid information disclosure
		result.Error = sanitizeBatchError(err)
		return result
	}

	result.Data = data
	result.Cached = cached
	return result
}

// sanitizeBatchError returns a safe error message for batch results.
func sanitizeBatchError(err error) string {
	switch {
	case errors.Is(err, rdap.ErrNotFound):
		return "not found"
	case errors.Is(err, rdap.ErrRateLimited):
		return "rate limited"
	case errors.Is(err, bootstrap.ErrNotFound):
		return "no RDAP server found"
	case errors.Is(err, bootstrap.ErrInvalidInput):
		return "invalid input"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	default:
		return "query failed"
	}
}

func (h *LookupHandler) lookupDomainData(ctx context.Context, name string) ([]byte, bool, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	cacheKey := cache.BuildKey(cache.KeyPrefixDomain, name)

	return h.cache.GetOrFetchWithNegative(ctx, cacheKey, func() ([]byte, error) {
		h.client.SetResolver(h.bootstrap.Resolver())

		resp, err := h.client.QueryDomain(ctx, name)
		if err != nil {
			return nil, err
		}

		rdapServer := ""
		if resolver := h.bootstrap.Resolver(); resolver != nil {
			if urls, resolveErr := resolver.ResolveDomain(name); resolveErr == nil && len(urls) > 0 {
				rdapServer = urls[0]
			}
		}

		result := schema.TransformDomain(resp, rdapServer)
		return json.Marshal(result)
	}, rdap.ErrNotFound)
}

func (h *LookupHandler) lookupIPData(ctx context.Context, addr string) ([]byte, bool, error) {
	addr = strings.TrimSpace(addr)
	cacheKey := cache.BuildKey(cache.KeyPrefixIP, addr)

	return h.cache.GetOrFetchWithNegative(ctx, cacheKey, func() ([]byte, error) {
		h.client.SetResolver(h.bootstrap.Resolver())

		resp, err := h.client.QueryIP(ctx, addr)
		if err != nil {
			return nil, err
		}

		rdapServer := ""
		if resolver := h.bootstrap.Resolver(); resolver != nil {
			if urls, resolveErr := resolver.ResolveIP(addr); resolveErr == nil && len(urls) > 0 {
				rdapServer = urls[0]
			}
		}

		result := schema.TransformIP(resp, rdapServer)
		return json.Marshal(result)
	}, rdap.ErrNotFound)
}

func (h *LookupHandler) lookupASNData(ctx context.Context, asnStr string) ([]byte, bool, error) {
	asnStr = strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(asnStr)), "AS")
	cacheKey := cache.BuildKey(cache.KeyPrefixASN, asnStr)

	return h.cache.GetOrFetchWithNegative(ctx, cacheKey, func() ([]byte, error) {
		asn64, err := strconv.ParseUint(asnStr, 10, 32)
		if err != nil {
			return nil, bootstrap.ErrInvalidInput
		}
		asn := uint32(asn64)

		h.client.SetResolver(h.bootstrap.Resolver())

		resp, err := h.client.QueryASN(ctx, asn)
		if err != nil {
			return nil, err
		}

		rdapServer := ""
		if resolver := h.bootstrap.Resolver(); resolver != nil {
			if urls, resolveErr := resolver.ResolveASN(asn); resolveErr == nil && len(urls) > 0 {
				rdapServer = urls[0]
			}
		}

		result := schema.TransformASN(resp, rdapServer)
		return json.Marshal(result)
	}, rdap.ErrNotFound)
}

func (h *LookupHandler) lookupEntityData(ctx context.Context, handle, serverURL string) ([]byte, bool, error) {
	handle = strings.TrimSpace(handle)
	// Include server URL in cache key to prevent cache poisoning
	cacheKey := cache.BuildKey(cache.KeyPrefixEntity, serverURL+":"+handle)

	return h.cache.GetOrFetchWithNegative(ctx, cacheKey, func() ([]byte, error) {
		resp, err := h.client.QueryEntity(ctx, handle, serverURL)
		if err != nil {
			return nil, err
		}

		result := schema.TransformEntityResponse(resp, serverURL)
		return json.Marshal(result)
	}, rdap.ErrNotFound)
}

func (h *LookupHandler) handleError(c echo.Context, err error, queryType, _ string) error {
	if errors.Is(err, rdap.ErrNotFound) {
		return c.JSON(http.StatusNotFound, ErrorResponse{
			Error: ErrorDetail{
				Code:    "NOT_FOUND",
				Message: queryType + " not found",
			},
		})
	}
	if errors.Is(err, rdap.ErrRateLimited) {
		return c.JSON(http.StatusTooManyRequests, ErrorResponse{
			Error: ErrorDetail{
				Code:    "RATE_LIMITED",
				Message: "Upstream RDAP server rate limit exceeded",
			},
		})
	}
	if errors.Is(err, bootstrap.ErrInvalidInput) {
		return c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: ErrorDetail{
				Code:    "INVALID_REQUEST",
				Message: "Invalid " + queryType + " format",
			},
		})
	}
	if errors.Is(err, bootstrap.ErrNotFound) {
		return c.JSON(http.StatusNotFound, ErrorResponse{
			Error: ErrorDetail{
				Code:    "NOT_FOUND",
				Message: "No RDAP server found for " + queryType,
			},
		})
	}

	// Sanitize upstream errors to avoid information disclosure
	return c.JSON(http.StatusBadGateway, ErrorResponse{
		Error: ErrorDetail{
			Code:    "UPSTREAM_ERROR",
			Message: sanitizeUpstreamError(err),
		},
	})
}

// sanitizeUpstreamError returns a safe error message for clients.
func sanitizeUpstreamError(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "Upstream server timeout"
	case errors.Is(err, rdap.ErrRateLimited):
		return "Upstream server rate limited"
	case errors.Is(err, rdap.ErrServerError):
		return "Upstream server error"
	default:
		return "Failed to query upstream RDAP server"
	}
}

func (h *LookupHandler) respondWithData(c echo.Context, data []byte, cached bool) error {
	if cached {
		c.Response().Header().Set("X-Cache", "HIT")
	} else {
		c.Response().Header().Set("X-Cache", "MISS")
	}

	c.Response().Header().Set("Content-Type", "application/json")
	c.Response().WriteHeader(http.StatusOK)
	_, err := c.Response().Write(data)
	return err
}

// ErrorResponse represents an error response.
type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail contains error details.
type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
