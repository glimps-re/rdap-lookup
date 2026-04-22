// Regression test for the concurrent map writes panic.
//
// The panic occurred when Echo reused a pooled *echo.Response for a new
// HTTP/1.1 keep-alive request while a previous request's handler goroutine
// was still alive and mutating the same response-header map.
//
// This test fires many concurrent requests over keep-alive connections through
// a real Echo server with SecureWithConfig middleware (the component that
// writes X-Frame-Options and similar headers). The cache is pre-warmed so
// every handler invocation returns a cached response immediately, exercising
// the header-write code path (respondWithData sets X-Cache: HIT) from many
// concurrent goroutines. The -race detector validates no data race occurs on
// the response-header maps.
package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/glimps-re/rdap-lookup/internal/cache"
	"github.com/glimps-re/rdap-lookup/internal/config"
	"github.com/glimps-re/rdap-lookup/internal/metrics"
	"github.com/glimps-re/rdap-lookup/internal/schema"
	"github.com/glimps-re/rdap-lookup/internal/validate"
)

// TestServer_KeepAlive_NoConcurrentMapWrites fires many concurrent requests
// on keep-alive HTTP/1.1 connections through a test Echo server. The lookup
// handler returns a pre-warmed cache hit so no upstream fetch is needed. The
// test asserts:
//
//   - All responses complete without error.
//   - No data race is detected by the -race detector on response-header maps.
//   - No goroutine leaks remain after all requests complete.
//
// This is a direct regression test for the concurrent-map-writes panic
// described in tmp/CONCURRENT_MAP_WRITES_FIX_PLAN.md.
func TestServer_KeepAlive_NoConcurrentMapWrites(t *testing.T) {
	const (
		handlerTimeout = 200 * time.Millisecond
		concurrency    = 20
		requestsPerCon = 10
	)

	// Build cache and pre-warm the test domain key so every handler call is a
	// cache hit (respondWithData path, sets X-Cache: HIT header), never
	// triggering a fetch that could hit nil bootstrap/client.
	cacheCfg := cache.DefaultTieredCacheConfig()
	tc, err := cache.NewTieredCache(cacheCfg)
	if err != nil {
		t.Fatalf("NewTieredCache: %v", err)
	}
	defer func() { _ = tc.Close() }()

	testDomain := "keepalive-test.example"
	cacheKey := cache.BuildKey(cache.KeyPrefixDomain, testDomain)

	// Pre-warm the cache with a valid (non-negative) domain response.
	fakeDomain := schema.SimpleDomain{
		Name:   testDomain,
		Status: []string{"active"},
	}
	fakeJSON, err := json.Marshal(fakeDomain)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if err := tc.SetWithDefaultTTL(context.Background(), cacheKey, fakeJSON, false); err != nil {
		t.Fatalf("SetWithDefaultTTL: %v", err)
	}

	m := metrics.New()
	logger := slog.New(slog.DiscardHandler)

	// LookupHandler backed by the pre-warmed cache. client/bootstrap are nil
	// intentionally: because every request is a cache hit, the fetch closure
	// (which would use them) is never invoked.
	h := &LookupHandler{
		cache:           tc,
		serverValidator: validate.NewRDAPServerValidator(nil),
		batchConfig:     config.BatchConfig{Concurrency: 10, Timeout: handlerTimeout},
		handlerTimeout:  handlerTimeout,
	}

	// Wire into a real Echo/Server with SecureWithConfig middleware so the
	// X-Frame-Options / X-Content-Type-Options header writes run alongside the
	// respondWithData X-Cache header write — the combination that caused the
	// original concurrent-map-writes panic.
	cfg := &config.Config{
		Server: config.ServerConfig{
			ListenAddr:      ":0",
			ReadTimeout:     5 * time.Second,
			WriteTimeout:    5 * time.Second,
			ShutdownTimeout: 5 * time.Second,
			TrustProxy:      false,
			BodyLimit:       "1MB",
		},
		Log: config.LogConfig{Level: "error", Format: "json"},
	}
	srv := NewServer(cfg, logger, m, BuildInfo{Version: "test"}, &ServerDeps{LookupHandler: h})
	ts := httptest.NewUnstartedServer(srv.Echo())
	ts.Config.ReadTimeout = 5 * time.Second
	ts.Config.WriteTimeout = 5 * time.Second
	ts.Start()
	// ts.Close() and srv.Shutdown() are called explicitly after wg.Wait() to
	// ensure server goroutines terminate before the goroutine leak check.

	// Shared transport with keep-alive so connections are reused across
	// goroutines; this is the exact topology that triggered the panic.
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   2 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        concurrency,
		MaxIdleConnsPerHost: concurrency,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}
	defer transport.CloseIdleConnections()

	var wg sync.WaitGroup
	for i := range concurrency {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for range requestsPerCon {
				url := ts.URL + "/api/v1/domain/" + testDomain
				req, reqErr := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
				if reqErr != nil {
					t.Errorf("goroutine %d: NewRequest: %v", id, reqErr)
					return
				}
				resp, doErr := client.Do(req)
				if doErr != nil {
					t.Errorf("goroutine %d: Do: %v", id, doErr)
					continue
				}
				if resp.StatusCode != http.StatusOK {
					t.Errorf("goroutine %d: status = %d, want 200", id, resp.StatusCode)
				}
				// Verify X-Cache header is set (respondWithData ran).
				if resp.Header.Get("X-Cache") == "" {
					t.Errorf("goroutine %d: X-Cache header missing", id)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}(i)
	}

	wg.Wait()

	// Close idle connections and shut down the test server so all server-side
	// goroutines (keep-alive conn.serve loops) terminate before the leak check.
	transport.CloseIdleConnections()
	ts.Close()
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutCancel()
	_ = srv.Shutdown(shutCtx)

	// Allow in-flight goroutines a brief settle window.
	time.Sleep(200 * time.Millisecond)

	// Verify no goroutine leaks from our handler code.
	goleak.VerifyNone(t,
		goleak.IgnoreTopFunction("net/http.(*persistConn).readLoop"),
		goleak.IgnoreTopFunction("net/http.(*persistConn).writeLoop"),
		goleak.IgnoreAnyFunction("net/http.(*Server).Serve"),
		goleak.IgnoreTopFunction("github.com/prometheus/client_golang/prometheus.(*goCollector).Start.func1"),
	)
}
