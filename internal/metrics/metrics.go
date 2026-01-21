// Package metrics provides Prometheus metrics for the rdap-lookup service.
package metrics

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Metrics holds all Prometheus metrics for the service.
type Metrics struct {
	// HTTP metrics (in-flight only, rest handled by echoprometheus)
	HTTPRequestsInFlight prometheus.Gauge

	// Cache metrics
	CacheHitsTotal      *prometheus.CounterVec
	CacheMissesTotal    *prometheus.CounterVec // Changed to CounterVec with layer label
	CacheSizeBytes      *prometheus.GaugeVec
	CacheEntries        *prometheus.GaugeVec
	CacheEvictionsTotal *prometheus.CounterVec

	// New cache metrics
	CacheOperationDuration  *prometheus.HistogramVec // get/set/delete timing per layer
	CachePromotionsTotal    prometheus.Counter       // L2 -> L1 promotions
	CachePromotionErrors    prometheus.Counter       // L2 -> L1 promotion failures
	CacheSingleflightTotal  *prometheus.CounterVec   // deduplication tracking
	CacheL2WriteErrorsTotal prometheus.Counter       // L2 write failures

	// RDAP upstream metrics (per-server)
	RDAPUpstreamRequestsTotal   *prometheus.CounterVec
	RDAPUpstreamRequestDuration *prometheus.HistogramVec
	RDAPUpstreamErrorsTotal     *prometheus.CounterVec
	RDAPUpstreamResponseSize    *prometheus.HistogramVec // response size tracking
	RDAPUpstreamRetriesTotal    *prometheus.CounterVec   // retry tracking
	RDAPUpstreamRateLimited     *prometheus.CounterVec   // 429 responses

	// RDAP client metrics (used by internal/rdap)
	RDAPClientRequestsTotal   *prometheus.CounterVec
	RDAPClientRequestDuration *prometheus.HistogramVec

	// Bootstrap metrics
	BootstrapLastRefresh   prometheus.Gauge
	BootstrapTLDsLoaded    prometheus.Gauge
	BootstrapRefreshErrors prometheus.Counter
	BootstrapIPRanges      prometheus.Gauge // IPv4 + IPv6 ranges
	BootstrapASNRanges     prometheus.Gauge // ASN ranges

	// Business metrics
	LookupsTotal       *prometheus.CounterVec
	LookupOutcomes     *prometheus.CounterVec // success/not_found/error/timeout breakdown
	LookupSource       *prometheus.CounterVec // l1_cache/l2_cache/upstream
	BatchRequestsTotal prometheus.Counter
	BatchSizeHistogram prometheus.Histogram

	// Security metrics
	SecurityEventsTotal *prometheus.CounterVec // validation_failed, ssrf_blocked, rate_limited, invalid_server

	// SSRF allowlist metrics
	SSRFAllowlistAge   prometheus.Gauge // Seconds since last update
	SSRFAllowlistStale prometheus.Gauge // 1 if stale, 0 if fresh

	// Rate limiter metrics
	RateLimiterEntries       prometheus.Gauge   // Current number of IP entries
	RateLimiterAtCapacity    prometheus.Counter // Times capacity was reached
	RateLimiterSubnetEntries prometheus.Gauge   // Current number of subnet entries

	// WHOIS client metrics
	WHOISRequestsTotal     *prometheus.CounterVec   // Labels: server, status (success/error/timeout)
	WHOISRequestDuration   *prometheus.HistogramVec // Labels: server
	WHOISFallbackTotal     *prometheus.CounterVec   // Labels: tld, reason (no_rdap_server)
	WHOISParseErrorsTotal  *prometheus.CounterVec   // Labels: tld
	WHOISResponseSizeBytes *prometheus.HistogramVec // Labels: server
	WHOISDiscoveryTotal    *prometheus.CounterVec   // Labels: tld, status (success/error/cached)
	WHOISDiscoveryDuration *prometheus.HistogramVec // IANA discovery timing
	WHOISServersCached     prometheus.Gauge         // Number of cached WHOIS servers
}

// New creates and registers all metrics.
func New() *Metrics {
	m := &Metrics{
		// HTTP metrics (in-flight only, rest handled by echoprometheus)
		HTTPRequestsInFlight: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Subsystem: "rdap",
				Name:      "http_requests_in_flight",
				Help:      "Current number of HTTP requests being processed",
			},
		),

		// Cache metrics
		CacheHitsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rdap_cache_hits_total",
				Help: "Total number of cache hits",
			},
			[]string{"layer"}, // "ram" or "redis"
		),
		CacheMissesTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rdap_cache_misses_total",
				Help: "Total number of cache misses",
			},
			[]string{"layer"}, // "ram" or "redis"
		),
		CacheSizeBytes: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "rdap_cache_size_bytes",
				Help: "Current cache size in bytes",
			},
			[]string{"layer"},
		),
		CacheEntries: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "rdap_cache_entries",
				Help: "Current number of cache entries",
			},
			[]string{"layer"},
		),
		CacheEvictionsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rdap_cache_evictions_total",
				Help: "Total number of cache evictions",
			},
			[]string{"layer"},
		),

		// New cache metrics
		CacheOperationDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "rdap_cache_operation_duration_seconds",
				Help:    "Cache operation duration in seconds",
				Buckets: []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1},
			},
			[]string{"layer", "operation"}, // layer: ram/redis, operation: get/set/delete
		),
		CachePromotionsTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "rdap_cache_promotions_total",
				Help: "Total number of cache promotions from L2 to L1",
			},
		),
		CachePromotionErrors: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "rdap_cache_promotion_errors_total",
				Help: "Total number of failed cache promotions from L2 to L1",
			},
		),
		CacheL2WriteErrorsTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "rdap_cache_l2_write_errors_total",
				Help: "Total number of L2 cache write failures",
			},
		),
		CacheSingleflightTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rdap_cache_singleflight_total",
				Help: "Total number of singleflight operations",
			},
			[]string{"result"}, // "shared" or "unique"
		),

		// RDAP upstream metrics (per-server)
		RDAPUpstreamRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rdap_upstream_requests_total",
				Help: "Total number of upstream RDAP requests",
			},
			[]string{"server", "status"},
		),
		RDAPUpstreamRequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "rdap_upstream_request_duration_seconds",
				Help:    "Upstream RDAP request duration in seconds",
				Buckets: []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10},
			},
			[]string{"server"},
		),
		RDAPUpstreamErrorsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rdap_upstream_errors_total",
				Help: "Total number of upstream RDAP errors",
			},
			[]string{"server", "error_type"},
		),
		RDAPUpstreamResponseSize: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "rdap_upstream_response_size_bytes",
				Help:    "Upstream RDAP response size in bytes",
				Buckets: []float64{1024, 4096, 16384, 65536, 262144, 1048576},
			},
			[]string{"server"},
		),
		RDAPUpstreamRetriesTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rdap_upstream_retries_total",
				Help: "Total number of upstream RDAP request retries",
			},
			[]string{"server"},
		),
		RDAPUpstreamRateLimited: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rdap_upstream_rate_limited_total",
				Help: "Total number of upstream RDAP rate limit responses (429)",
			},
			[]string{"server"},
		),

		// RDAP client metrics
		RDAPClientRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rdap_client_requests_total",
				Help: "Total number of RDAP client requests by type and status",
			},
			[]string{"type", "status"},
		),
		RDAPClientRequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "rdap_client_request_duration_seconds",
				Help:    "RDAP client request duration in seconds",
				Buckets: []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10},
			},
			[]string{"type"},
		),

		// Bootstrap metrics
		BootstrapLastRefresh: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "rdap_bootstrap_last_refresh_timestamp",
				Help: "Unix timestamp of last successful bootstrap refresh",
			},
		),
		BootstrapTLDsLoaded: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "rdap_bootstrap_tlds_loaded",
				Help: "Number of TLDs loaded from bootstrap",
			},
		),
		BootstrapRefreshErrors: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "rdap_bootstrap_refresh_errors_total",
				Help: "Total number of bootstrap refresh errors",
			},
		),
		BootstrapIPRanges: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "rdap_bootstrap_ip_ranges_loaded",
				Help: "Number of IP ranges loaded from bootstrap",
			},
		),
		BootstrapASNRanges: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "rdap_bootstrap_asn_ranges_loaded",
				Help: "Number of ASN ranges loaded from bootstrap",
			},
		),

		// Business metrics
		LookupsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rdap_lookups_total",
				Help: "Total number of RDAP lookups",
			},
			[]string{"type"}, // domain, ip, asn, entity, nameserver
		),
		LookupOutcomes: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rdap_lookup_outcomes_total",
				Help: "Total number of RDAP lookup outcomes",
			},
			[]string{"type", "outcome"}, // outcome: success, not_found, error, timeout, rate_limited
		),
		LookupSource: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rdap_lookup_source_total",
				Help: "Total number of RDAP lookups by data source",
			},
			[]string{"type", "source"}, // source: l1_cache, l2_cache, upstream
		),
		BatchRequestsTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "rdap_batch_requests_total",
				Help: "Total number of batch lookup requests",
			},
		),
		BatchSizeHistogram: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "rdap_batch_size",
				Help:    "Distribution of batch request sizes",
				Buckets: []float64{1, 5, 10, 25, 50, 100},
			},
		),

		// Security metrics
		SecurityEventsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rdap_security_events_total",
				Help: "Total security events by type (validation_failed, ssrf_blocked, rate_limited, invalid_server)",
			},
			[]string{"event_type"},
		),

		// SSRF allowlist metrics
		SSRFAllowlistAge: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "rdap_ssrf_allowlist_age_seconds",
				Help: "Seconds since SSRF allowlist was last updated",
			},
		),
		SSRFAllowlistStale: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "rdap_ssrf_allowlist_stale",
				Help: "1 if SSRF allowlist is stale (>2x refresh interval), 0 otherwise",
			},
		),

		// Rate limiter metrics
		RateLimiterEntries: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "rdap_rate_limiter_entries",
				Help: "Current number of IP rate limiter entries",
			},
		),
		RateLimiterAtCapacity: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "rdap_rate_limiter_at_capacity_total",
				Help: "Number of times rate limiter reached capacity",
			},
		),
		RateLimiterSubnetEntries: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "rdap_rate_limiter_subnet_entries",
				Help: "Current number of subnet rate limiter entries (fallback)",
			},
		),

		// WHOIS client metrics
		WHOISRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rdap_whois_requests_total",
				Help: "Total number of WHOIS requests",
			},
			[]string{"server", "status"}, // status: success, error, timeout
		),
		WHOISRequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "rdap_whois_request_duration_seconds",
				Help:    "WHOIS request duration in seconds",
				Buckets: []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10},
			},
			[]string{"server"},
		),
		WHOISFallbackTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rdap_whois_fallback_total",
				Help: "Total number of WHOIS fallback events",
			},
			[]string{"tld", "reason"}, // reason: no_rdap_server
		),
		WHOISParseErrorsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rdap_whois_parse_errors_total",
				Help: "Total number of WHOIS parse errors",
			},
			[]string{"tld"},
		),
		WHOISResponseSizeBytes: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "rdap_whois_response_size_bytes",
				Help:    "WHOIS response size in bytes",
				Buckets: []float64{1024, 2048, 4096, 8192, 16384, 32768, 65536},
			},
			[]string{"server"},
		),
		WHOISDiscoveryTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "rdap_whois_discovery_total",
				Help: "Total number of WHOIS server discovery attempts",
			},
			[]string{"tld", "status"}, // status: success, error, cached
		),
		WHOISDiscoveryDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "rdap_whois_discovery_duration_seconds",
				Help:    "WHOIS server discovery (IANA query) duration in seconds",
				Buckets: []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10},
			},
			[]string{},
		),
		WHOISServersCached: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "rdap_whois_servers_cached",
				Help: "Number of WHOIS servers in discovery cache",
			},
		),
	}

	return m
}

// Register registers all metrics with the default prometheus registry.
func (m *Metrics) Register() error {
	// Register default Go runtime metrics
	if err := prometheus.Register(collectors.NewGoCollector()); err != nil {
		// Ignore if already registered
		var alreadyRegistered prometheus.AlreadyRegisteredError
		if !errors.As(err, &alreadyRegistered) {
			return err
		}
	}

	// Register all custom metrics
	metricCollectors := []prometheus.Collector{
		// HTTP metrics
		m.HTTPRequestsInFlight,

		// Cache metrics
		m.CacheHitsTotal,
		m.CacheMissesTotal,
		m.CacheSizeBytes,
		m.CacheEntries,
		m.CacheEvictionsTotal,
		m.CacheOperationDuration,
		m.CachePromotionsTotal,
		m.CachePromotionErrors,
		m.CacheL2WriteErrorsTotal,
		m.CacheSingleflightTotal,

		// RDAP upstream metrics
		m.RDAPUpstreamRequestsTotal,
		m.RDAPUpstreamRequestDuration,
		m.RDAPUpstreamErrorsTotal,
		m.RDAPUpstreamResponseSize,
		m.RDAPUpstreamRetriesTotal,
		m.RDAPUpstreamRateLimited,

		// RDAP client metrics
		m.RDAPClientRequestsTotal,
		m.RDAPClientRequestDuration,

		// Bootstrap metrics
		m.BootstrapLastRefresh,
		m.BootstrapTLDsLoaded,
		m.BootstrapRefreshErrors,
		m.BootstrapIPRanges,
		m.BootstrapASNRanges,

		// Business metrics
		m.LookupsTotal,
		m.LookupOutcomes,
		m.LookupSource,
		m.BatchRequestsTotal,
		m.BatchSizeHistogram,

		// Security metrics
		m.SecurityEventsTotal,

		// SSRF allowlist metrics
		m.SSRFAllowlistAge,
		m.SSRFAllowlistStale,

		// Rate limiter metrics
		m.RateLimiterEntries,
		m.RateLimiterAtCapacity,
		m.RateLimiterSubnetEntries,

		// WHOIS metrics
		m.WHOISRequestsTotal,
		m.WHOISRequestDuration,
		m.WHOISFallbackTotal,
		m.WHOISParseErrorsTotal,
		m.WHOISResponseSizeBytes,
		m.WHOISDiscoveryTotal,
		m.WHOISDiscoveryDuration,
		m.WHOISServersCached,
	}

	for _, c := range metricCollectors {
		if err := prometheus.Register(c); err != nil {
			// Ignore if already registered
			var alreadyRegistered prometheus.AlreadyRegisteredError
			if !errors.As(err, &alreadyRegistered) {
				return err
			}
		}
	}

	return nil
}

// MustRegister registers all metrics and panics on error.
func (m *Metrics) MustRegister() {
	if err := m.Register(); err != nil {
		panic(err)
	}
}

// CacheMetricsCollector implements the cache.MetricsCollector interface.
// It bridges the cache package to the Prometheus metrics.
type CacheMetricsCollector struct {
	m *Metrics
}

// NewCacheMetricsCollector creates a new CacheMetricsCollector.
func NewCacheMetricsCollector(m *Metrics) *CacheMetricsCollector {
	return &CacheMetricsCollector{m: m}
}

// RecordHit records a cache hit for the given layer.
func (c *CacheMetricsCollector) RecordHit(layer string) {
	c.m.CacheHitsTotal.WithLabelValues(layer).Inc()
}

// RecordMiss records a cache miss for the given layer.
func (c *CacheMetricsCollector) RecordMiss(layer string) {
	c.m.CacheMissesTotal.WithLabelValues(layer).Inc()
}

// RecordEviction records a cache eviction for the given layer.
func (c *CacheMetricsCollector) RecordEviction(layer string) {
	c.m.CacheEvictionsTotal.WithLabelValues(layer).Inc()
}

// SetSize sets the current cache size in bytes for the given layer.
func (c *CacheMetricsCollector) SetSize(layer string, sizeBytes int64) {
	c.m.CacheSizeBytes.WithLabelValues(layer).Set(float64(sizeBytes))
}

// SetEntries sets the current number of entries for the given layer.
func (c *CacheMetricsCollector) SetEntries(layer string, count int) {
	c.m.CacheEntries.WithLabelValues(layer).Set(float64(count))
}

// RecordOperationDuration records the duration of a cache operation.
func (c *CacheMetricsCollector) RecordOperationDuration(layer, operation string, seconds float64) {
	c.m.CacheOperationDuration.WithLabelValues(layer, operation).Observe(seconds)
}

// RecordPromotion records a cache promotion from L2 to L1.
func (c *CacheMetricsCollector) RecordPromotion() {
	c.m.CachePromotionsTotal.Inc()
}

// RecordPromotionError records a failed L2->L1 promotion.
func (c *CacheMetricsCollector) RecordPromotionError() {
	c.m.CachePromotionErrors.Inc()
}

// RecordL2WriteError records an L2 cache write failure.
func (c *CacheMetricsCollector) RecordL2WriteError() {
	c.m.CacheL2WriteErrorsTotal.Inc()
}

// RecordSingleflight records a singleflight operation result.
func (c *CacheMetricsCollector) RecordSingleflight(shared bool) {
	if shared {
		c.m.CacheSingleflightTotal.WithLabelValues("shared").Inc()
	} else {
		c.m.CacheSingleflightTotal.WithLabelValues("unique").Inc()
	}
}
