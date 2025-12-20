package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestNew(t *testing.T) {
	m := New()

	// HTTP metrics (only in-flight, rest handled by echoprometheus)
	if m.HTTPRequestsInFlight == nil {
		t.Error("HTTPRequestsInFlight is nil")
	}

	// Cache metrics
	if m.CacheHitsTotal == nil {
		t.Error("CacheHitsTotal is nil")
	}
	if m.CacheMissesTotal == nil {
		t.Error("CacheMissesTotal is nil")
	}
	if m.CacheOperationDuration == nil {
		t.Error("CacheOperationDuration is nil")
	}
	if m.CachePromotionsTotal == nil {
		t.Error("CachePromotionsTotal is nil")
	}
	if m.CacheSingleflightTotal == nil {
		t.Error("CacheSingleflightTotal is nil")
	}

	// Upstream metrics
	if m.RDAPUpstreamRequestsTotal == nil {
		t.Error("RDAPUpstreamRequestsTotal is nil")
	}
	if m.RDAPUpstreamResponseSize == nil {
		t.Error("RDAPUpstreamResponseSize is nil")
	}
	if m.RDAPUpstreamRetriesTotal == nil {
		t.Error("RDAPUpstreamRetriesTotal is nil")
	}
	if m.RDAPUpstreamRateLimited == nil {
		t.Error("RDAPUpstreamRateLimited is nil")
	}

	// Business metrics
	if m.LookupsTotal == nil {
		t.Error("LookupsTotal is nil")
	}
	if m.LookupOutcomes == nil {
		t.Error("LookupOutcomes is nil")
	}
	if m.LookupSource == nil {
		t.Error("LookupSource is nil")
	}
	if m.BatchRequestsTotal == nil {
		t.Error("BatchRequestsTotal is nil")
	}

	// Bootstrap metrics
	if m.BootstrapIPRanges == nil {
		t.Error("BootstrapIPRanges is nil")
	}
	if m.BootstrapASNRanges == nil {
		t.Error("BootstrapASNRanges is nil")
	}
}

func TestMetrics_Register(t *testing.T) {
	// Use a custom registry to avoid conflicts with other tests
	reg := prometheus.NewRegistry()

	m := New()

	// Register with custom registry
	collectors := []prometheus.Collector{
		m.HTTPRequestsInFlight,
		m.CacheHitsTotal,
		m.CacheMissesTotal,
		m.CacheOperationDuration,
		m.CachePromotionsTotal,
		m.CacheSingleflightTotal,
	}

	for _, c := range collectors {
		if err := reg.Register(c); err != nil {
			t.Fatalf("failed to register collector: %v", err)
		}
	}
}

func TestHTTPRequestsInFlight(t *testing.T) {
	m := New()

	m.HTTPRequestsInFlight.Inc()
	m.HTTPRequestsInFlight.Inc()

	if val := testutil.ToFloat64(m.HTTPRequestsInFlight); val != 2 {
		t.Errorf("in flight = %v, want 2", val)
	}

	m.HTTPRequestsInFlight.Dec()

	if val := testutil.ToFloat64(m.HTTPRequestsInFlight); val != 1 {
		t.Errorf("in flight = %v, want 1", val)
	}
}

func TestCacheMetrics(t *testing.T) {
	m := New()

	// Test cache hits
	m.CacheHitsTotal.WithLabelValues("ram").Inc()
	m.CacheHitsTotal.WithLabelValues("ram").Inc()
	m.CacheHitsTotal.WithLabelValues("redis").Inc()

	ramHits := testutil.ToFloat64(m.CacheHitsTotal.WithLabelValues("ram"))
	if ramHits != 2 {
		t.Errorf("RAM hits = %v, want 2", ramHits)
	}

	redisHits := testutil.ToFloat64(m.CacheHitsTotal.WithLabelValues("redis"))
	if redisHits != 1 {
		t.Errorf("Redis hits = %v, want 1", redisHits)
	}

	// Test cache misses (now with layer label)
	m.CacheMissesTotal.WithLabelValues("ram").Inc()
	m.CacheMissesTotal.WithLabelValues("redis").Inc()
	ramMisses := testutil.ToFloat64(m.CacheMissesTotal.WithLabelValues("ram"))
	if ramMisses != 1 {
		t.Errorf("RAM cache misses = %v, want 1", ramMisses)
	}

	// Test cache size
	m.CacheSizeBytes.WithLabelValues("ram").Set(1024 * 1024)
	size := testutil.ToFloat64(m.CacheSizeBytes.WithLabelValues("ram"))
	if size != 1024*1024 {
		t.Errorf("cache size = %v, want 1MB", size)
	}

	// Test cache operation duration
	m.CacheOperationDuration.WithLabelValues("ram", "get").Observe(0.001)
	m.CacheOperationDuration.WithLabelValues("redis", "set").Observe(0.005)
	count := testutil.CollectAndCount(m.CacheOperationDuration)
	if count != 2 {
		t.Errorf("cache operation duration count = %v, want 2", count)
	}

	// Test cache promotions
	m.CachePromotionsTotal.Inc()
	promotions := testutil.ToFloat64(m.CachePromotionsTotal)
	if promotions != 1 {
		t.Errorf("cache promotions = %v, want 1", promotions)
	}

	// Test singleflight
	m.CacheSingleflightTotal.WithLabelValues("shared").Inc()
	m.CacheSingleflightTotal.WithLabelValues("unique").Inc()
	shared := testutil.ToFloat64(m.CacheSingleflightTotal.WithLabelValues("shared"))
	if shared != 1 {
		t.Errorf("singleflight shared = %v, want 1", shared)
	}
}

func TestUpstreamMetrics(t *testing.T) {
	m := New()

	// Test upstream requests
	m.RDAPUpstreamRequestsTotal.WithLabelValues("rdap.verisign.com", "200").Inc()
	m.RDAPUpstreamRequestsTotal.WithLabelValues("rdap.verisign.com", "404").Inc()

	okCount := testutil.ToFloat64(m.RDAPUpstreamRequestsTotal.WithLabelValues("rdap.verisign.com", "200"))
	if okCount != 1 {
		t.Errorf("upstream OK count = %v, want 1", okCount)
	}

	// Test upstream duration
	m.RDAPUpstreamRequestDuration.WithLabelValues("rdap.verisign.com").Observe(0.5)
	count := testutil.CollectAndCount(m.RDAPUpstreamRequestDuration)
	if count != 1 {
		t.Errorf("upstream duration count = %v, want 1", count)
	}

	// Test upstream response size
	m.RDAPUpstreamResponseSize.WithLabelValues("rdap.verisign.com").Observe(4096)
	sizeCount := testutil.CollectAndCount(m.RDAPUpstreamResponseSize)
	if sizeCount != 1 {
		t.Errorf("upstream response size count = %v, want 1", sizeCount)
	}

	// Test upstream retries
	m.RDAPUpstreamRetriesTotal.WithLabelValues("rdap.verisign.com").Inc()
	retries := testutil.ToFloat64(m.RDAPUpstreamRetriesTotal.WithLabelValues("rdap.verisign.com"))
	if retries != 1 {
		t.Errorf("upstream retries = %v, want 1", retries)
	}

	// Test upstream rate limited
	m.RDAPUpstreamRateLimited.WithLabelValues("rdap.verisign.com").Inc()
	rateLimited := testutil.ToFloat64(m.RDAPUpstreamRateLimited.WithLabelValues("rdap.verisign.com"))
	if rateLimited != 1 {
		t.Errorf("upstream rate limited = %v, want 1", rateLimited)
	}

	// Test upstream errors
	m.RDAPUpstreamErrorsTotal.WithLabelValues("rdap.verisign.com", "timeout").Inc()
	errors := testutil.ToFloat64(m.RDAPUpstreamErrorsTotal.WithLabelValues("rdap.verisign.com", "timeout"))
	if errors != 1 {
		t.Errorf("upstream errors = %v, want 1", errors)
	}
}

func TestLookupsTotal(t *testing.T) {
	m := New()

	m.LookupsTotal.WithLabelValues("domain").Inc()
	m.LookupsTotal.WithLabelValues("domain").Inc()
	m.LookupsTotal.WithLabelValues("ip").Inc()
	m.LookupsTotal.WithLabelValues("asn").Inc()

	domainCount := testutil.ToFloat64(m.LookupsTotal.WithLabelValues("domain"))
	if domainCount != 2 {
		t.Errorf("domain lookups = %v, want 2", domainCount)
	}

	ipCount := testutil.ToFloat64(m.LookupsTotal.WithLabelValues("ip"))
	if ipCount != 1 {
		t.Errorf("ip lookups = %v, want 1", ipCount)
	}
}

func TestLookupOutcomes(t *testing.T) {
	m := New()

	m.LookupOutcomes.WithLabelValues("domain", "success").Inc()
	m.LookupOutcomes.WithLabelValues("domain", "not_found").Inc()
	m.LookupOutcomes.WithLabelValues("ip", "error").Inc()

	success := testutil.ToFloat64(m.LookupOutcomes.WithLabelValues("domain", "success"))
	if success != 1 {
		t.Errorf("domain success = %v, want 1", success)
	}

	notFound := testutil.ToFloat64(m.LookupOutcomes.WithLabelValues("domain", "not_found"))
	if notFound != 1 {
		t.Errorf("domain not_found = %v, want 1", notFound)
	}
}

func TestLookupSource(t *testing.T) {
	m := New()

	m.LookupSource.WithLabelValues("domain", "l1_cache").Inc()
	m.LookupSource.WithLabelValues("domain", "l2_cache").Inc()
	m.LookupSource.WithLabelValues("domain", "upstream").Inc()

	l1 := testutil.ToFloat64(m.LookupSource.WithLabelValues("domain", "l1_cache"))
	if l1 != 1 {
		t.Errorf("domain l1_cache = %v, want 1", l1)
	}

	upstream := testutil.ToFloat64(m.LookupSource.WithLabelValues("domain", "upstream"))
	if upstream != 1 {
		t.Errorf("domain upstream = %v, want 1", upstream)
	}
}

func TestBatchMetrics(t *testing.T) {
	m := New()

	m.BatchRequestsTotal.Inc()
	m.BatchRequestsTotal.Inc()

	batchCount := testutil.ToFloat64(m.BatchRequestsTotal)
	if batchCount != 2 {
		t.Errorf("batch requests = %v, want 2", batchCount)
	}

	m.BatchSizeHistogram.Observe(5)
	m.BatchSizeHistogram.Observe(10)
	m.BatchSizeHistogram.Observe(50)

	// For histograms, use CollectAndCount instead of ToFloat64
	histCount := testutil.CollectAndCount(m.BatchSizeHistogram)
	if histCount != 1 { // One histogram
		t.Errorf("batch size histogram count = %v, want 1", histCount)
	}
}

func TestBootstrapMetrics(t *testing.T) {
	m := New()

	m.BootstrapLastRefresh.Set(1234567890)
	if val := testutil.ToFloat64(m.BootstrapLastRefresh); val != 1234567890 {
		t.Errorf("bootstrap last refresh = %v, want 1234567890", val)
	}

	m.BootstrapTLDsLoaded.Set(1500)
	if val := testutil.ToFloat64(m.BootstrapTLDsLoaded); val != 1500 {
		t.Errorf("bootstrap TLDs loaded = %v, want 1500", val)
	}

	m.BootstrapIPRanges.Set(500)
	if val := testutil.ToFloat64(m.BootstrapIPRanges); val != 500 {
		t.Errorf("bootstrap IP ranges = %v, want 500", val)
	}

	m.BootstrapASNRanges.Set(200)
	if val := testutil.ToFloat64(m.BootstrapASNRanges); val != 200 {
		t.Errorf("bootstrap ASN ranges = %v, want 200", val)
	}

	m.BootstrapRefreshErrors.Inc()
	if val := testutil.ToFloat64(m.BootstrapRefreshErrors); val != 1 {
		t.Errorf("bootstrap refresh errors = %v, want 1", val)
	}
}
