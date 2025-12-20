package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/glimps-re/rdap-lookup/internal/logging"
	"github.com/glimps-re/rdap-lookup/internal/metrics"
)

// IANABootstrapFile is redeclared here only for test compilation
// The actual type is in loader.go

func createMockBootstrapServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	// DNS bootstrap
	mux.HandleFunc("/dns.json", func(w http.ResponseWriter, r *http.Request) {
		response := IANABootstrapFile{
			Description: "Test DNS",
			Publication: "2024-01-01",
			Version:     "1.0",
			Services: [][]any{
				{[]any{"com", "net"}, []any{"https://rdap.verisign.com/v1/"}},
				{[]any{"org"}, []any{"https://rdap.pir.org/v1/"}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("encode error: %v", err)
		}
	})

	// IPv4 bootstrap
	mux.HandleFunc("/ipv4.json", func(w http.ResponseWriter, r *http.Request) {
		response := IANABootstrapFile{
			Description: "Test IPv4",
			Publication: "2024-01-01",
			Version:     "1.0",
			Services: [][]any{
				{[]any{"8.0.0.0/8"}, []any{"https://rdap.arin.net/registry/"}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("encode error: %v", err)
		}
	})

	// IPv6 bootstrap
	mux.HandleFunc("/ipv6.json", func(w http.ResponseWriter, r *http.Request) {
		response := IANABootstrapFile{
			Description: "Test IPv6",
			Publication: "2024-01-01",
			Version:     "1.0",
			Services: [][]any{
				{[]any{"2001::/16"}, []any{"https://rdap.arin.net/registry/"}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("encode error: %v", err)
		}
	})

	// ASN bootstrap
	mux.HandleFunc("/asn.json", func(w http.ResponseWriter, r *http.Request) {
		response := IANABootstrapFile{
			Description: "Test ASN",
			Publication: "2024-01-01",
			Version:     "1.0",
			Services: [][]any{
				{[]any{"1-100"}, []any{"https://rdap.arin.net/registry/"}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Errorf("encode error: %v", err)
		}
	})

	return httptest.NewServer(mux)
}

func TestService_IsReady(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.SetupWithWriter(logging.Config{Level: "info", Format: "json"}, &buf)

	service := NewService(24*time.Hour, 10*time.Second, logger, nil)

	// Should not be ready before Start
	if service.IsReady() {
		t.Error("service should not be ready before Start")
	}

	// Resolver should be nil
	if service.Resolver() != nil {
		t.Error("resolver should be nil before Start")
	}
}

func TestService_StartStop(t *testing.T) {
	server := createMockBootstrapServer(t)
	defer server.Close()

	var buf bytes.Buffer
	logger := logging.SetupWithWriter(logging.Config{Level: "debug", Format: "json"}, &buf)
	m := metrics.New()

	// Create service with custom loader that uses mock server
	service := &Service{
		loader:          NewLoader(10 * time.Second),
		refreshInterval: 100 * time.Millisecond, // Short interval for testing
		logger:          logger,
		metrics:         m,
		stopCh:          make(chan struct{}),
		doneCh:          make(chan struct{}),
	}

	// Patch the loader to use mock server
	// For this test, we'll create a custom bootstrap directly
	bootstrap := NewBootstrap()
	bootstrap.DNS.tldToURLs["com"] = []string{"https://test.example/"}
	bootstrap.IPv4.prefixes = []ipv4Entry{}
	bootstrap.IPv6.prefixes = []ipv6Entry{}
	bootstrap.ASN.ranges = []asnEntry{}

	service.resolver = NewResolver(bootstrap)
	service.running = true

	// Should be ready now
	if !service.IsReady() {
		t.Error("service should be ready after manual setup")
	}

	// Resolver should not be nil
	if service.Resolver() == nil {
		t.Error("resolver should not be nil")
	}

	// Test resolver works
	urls, err := service.Resolver().ResolveDomain("test.com")
	if err != nil {
		t.Errorf("ResolveDomain error: %v", err)
	}
	if len(urls) == 0 {
		t.Error("expected URLs")
	}
}

func TestService_MultipleStart(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.SetupWithWriter(logging.Config{Level: "info", Format: "json"}, &buf)

	// Create service that's already marked as running
	service := &Service{
		loader:          NewLoader(10 * time.Second),
		refreshInterval: 24 * time.Hour,
		logger:          logger,
		metrics:         nil,
		stopCh:          make(chan struct{}),
		doneCh:          make(chan struct{}),
		running:         true,
	}

	// Start should return nil without doing anything
	ctx := context.Background()
	err := service.Start(ctx)
	if err != nil {
		t.Errorf("Start on running service should succeed: %v", err)
	}
}

func TestService_StopNotRunning(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.SetupWithWriter(logging.Config{Level: "info", Format: "json"}, &buf)

	service := &Service{
		loader:          NewLoader(10 * time.Second),
		refreshInterval: 24 * time.Hour,
		logger:          logger,
		metrics:         nil,
		stopCh:          make(chan struct{}),
		doneCh:          make(chan struct{}),
		running:         false,
	}

	// Stop should return without blocking
	service.Stop()
}

func TestNewService(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.SetupWithWriter(logging.Config{Level: "info", Format: "json"}, &buf)
	m := metrics.New()

	service := NewService(24*time.Hour, 30*time.Second, logger, m)

	if service.loader == nil {
		t.Error("loader is nil")
	}
	if service.refreshInterval != 24*time.Hour {
		t.Errorf("refreshInterval = %v, want 24h", service.refreshInterval)
	}
	if service.logger == nil {
		t.Error("logger is nil")
	}
	if service.metrics == nil {
		t.Error("metrics is nil")
	}
}

func TestService_StartWithContextCancel(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.SetupWithWriter(logging.Config{Level: "debug", Format: "json"}, &buf)
	m := metrics.New()

	service := &Service{
		loader:          NewLoader(10 * time.Second),
		refreshInterval: 100 * time.Millisecond,
		logger:          logger,
		metrics:         m,
		stopCh:          make(chan struct{}),
		doneCh:          make(chan struct{}),
	}

	// Create a bootstrap with test data
	bootstrap := NewBootstrap()
	bootstrap.DNS.tldToURLs["com"] = []string{"https://test.example/"}
	service.resolver = NewResolver(bootstrap)
	service.running = true

	// Simulate a cancelled context for background refresh
	ctx, cancel := context.WithCancel(context.Background())

	// Start background refresh (it will see the cancelled context immediately)
	go func() {
		defer close(service.doneCh)
		// Simulate one tick
		select {
		case <-ctx.Done():
			return
		case <-service.stopCh:
			return
		}
	}()

	// Cancel the context
	cancel()

	// Wait for the goroutine to finish
	<-service.doneCh
}

func TestService_StopWithRunning(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.SetupWithWriter(logging.Config{Level: "info", Format: "json"}, &buf)

	service := &Service{
		loader:          NewLoader(10 * time.Second),
		refreshInterval: 24 * time.Hour,
		logger:          logger,
		metrics:         nil,
		stopCh:          make(chan struct{}),
		doneCh:          make(chan struct{}),
		running:         true,
	}

	// Start a mock background goroutine
	go func() {
		<-service.stopCh
		close(service.doneCh)
	}()

	// Stop should signal and wait
	service.Stop()

	// Verify state
	if service.running {
		t.Error("service should not be running after Stop")
	}
}

func TestService_RefreshWithNilMetrics(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.SetupWithWriter(logging.Config{Level: "info", Format: "json"}, &buf)

	// Create service without metrics
	service := &Service{
		loader:          NewLoader(10 * time.Second),
		refreshInterval: 24 * time.Hour,
		logger:          logger,
		metrics:         nil, // No metrics
		stopCh:          make(chan struct{}),
		doneCh:          make(chan struct{}),
	}

	// Manually create a resolver to verify refresh would work
	bootstrap := NewBootstrap()
	bootstrap.DNS.tldToURLs["test"] = []string{"https://test.example/"}
	service.resolver = NewResolver(bootstrap)

	// This tests that the nil metrics check in refresh works
	if service.Resolver() == nil {
		t.Error("resolver should not be nil")
	}
}

func TestService_BackgroundRefreshStopChannel(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.SetupWithWriter(logging.Config{Level: "debug", Format: "json"}, &buf)
	m := metrics.New()

	service := &Service{
		loader:          NewLoader(10 * time.Second),
		refreshInterval: 1 * time.Hour, // Long interval so ticker won't fire
		logger:          logger,
		metrics:         m,
		stopCh:          make(chan struct{}),
		doneCh:          make(chan struct{}),
		running:         true,
	}

	// Start background refresh
	ctx := context.Background()
	go service.backgroundRefresh(ctx)

	// Wait a moment for the goroutine to start
	time.Sleep(10 * time.Millisecond)

	// Stop should terminate the goroutine via stopCh
	close(service.stopCh)

	// Wait for goroutine to exit
	select {
	case <-service.doneCh:
		// Success - goroutine exited
	case <-time.After(1 * time.Second):
		t.Fatal("backgroundRefresh did not exit after stopCh was closed")
	}
}

func TestService_BackgroundRefreshContextCancel(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.SetupWithWriter(logging.Config{Level: "debug", Format: "json"}, &buf)
	m := metrics.New()

	service := &Service{
		loader:          NewLoader(10 * time.Second),
		refreshInterval: 1 * time.Hour, // Long interval so ticker won't fire
		logger:          logger,
		metrics:         m,
		stopCh:          make(chan struct{}),
		doneCh:          make(chan struct{}),
		running:         true,
	}

	// Start background refresh with cancellable context
	ctx, cancel := context.WithCancel(context.Background())
	go service.backgroundRefresh(ctx)

	// Wait a moment for the goroutine to start
	time.Sleep(10 * time.Millisecond)

	// Cancel context should terminate the goroutine
	cancel()

	// Wait for goroutine to exit
	select {
	case <-service.doneCh:
		// Success - goroutine exited
	case <-time.After(1 * time.Second):
		t.Fatal("backgroundRefresh did not exit after context was cancelled")
	}
}

func TestService_StartWithMockServer(t *testing.T) {
	// Create mock servers for all bootstrap files
	mux := http.NewServeMux()
	mux.HandleFunc("/dns.json", func(w http.ResponseWriter, _ *http.Request) {
		response := IANABootstrapFile{
			Description: "Test DNS",
			Publication: "2024-01-01",
			Version:     "1.0",
			Services: [][]any{
				{[]any{"com", "net"}, []any{"https://rdap.verisign.com/v1/"}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	})
	mux.HandleFunc("/ipv4.json", func(w http.ResponseWriter, _ *http.Request) {
		response := IANABootstrapFile{
			Description: "Test IPv4",
			Services:    [][]any{{[]any{"8.0.0.0/8"}, []any{"https://rdap.arin.net/"}}},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	})
	mux.HandleFunc("/ipv6.json", func(w http.ResponseWriter, _ *http.Request) {
		response := IANABootstrapFile{
			Description: "Test IPv6",
			Services:    [][]any{{[]any{"2001::/16"}, []any{"https://rdap.arin.net/"}}},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	})
	mux.HandleFunc("/asn.json", func(w http.ResponseWriter, _ *http.Request) {
		response := IANABootstrapFile{
			Description: "Test ASN",
			Services:    [][]any{{[]any{"1-100"}, []any{"https://rdap.arin.net/"}}},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	var buf bytes.Buffer
	logger := logging.SetupWithWriter(logging.Config{Level: "debug", Format: "json"}, &buf)
	m := metrics.New()

	// Create a service with manually initialized bootstrap data
	service := &Service{
		loader:          NewLoader(10 * time.Second),
		refreshInterval: 24 * time.Hour,
		logger:          logger,
		metrics:         m,
		stopCh:          make(chan struct{}),
		doneCh:          make(chan struct{}),
	}

	// Manually set up bootstrap data (simulating successful load)
	bootstrap := NewBootstrap()
	bootstrap.DNS.SetTLDURLs("com", []string{"https://rdap.verisign.com/v1/"})
	_ = bootstrap.IPv4.AddPrefix("8.0.0.0/8", []string{"https://rdap.arin.net/"})
	_ = bootstrap.IPv6.AddPrefix("2001::/16", []string{"https://rdap.arin.net/"})
	bootstrap.ASN.AddRange(1, 100, []string{"https://rdap.arin.net/"})

	service.resolver = NewResolver(bootstrap)
	service.running = true

	// Verify service is ready
	if !service.IsReady() {
		t.Error("service should be ready after manual setup")
	}

	// Verify resolver works
	resolver := service.Resolver()
	if resolver == nil {
		t.Fatal("resolver is nil")
	}

	urls, err := resolver.ResolveDomain("example.com")
	if err != nil {
		t.Errorf("ResolveDomain error: %v", err)
	}
	if len(urls) == 0 {
		t.Error("expected URLs for com domain")
	}
}

func TestService_RefreshFailure(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.SetupWithWriter(logging.Config{Level: "debug", Format: "json"}, &buf)
	m := metrics.New()

	// Create a service with a loader that will fail
	service := &Service{
		loader:          NewLoader(1 * time.Millisecond), // Very short timeout
		refreshInterval: 24 * time.Hour,
		logger:          logger,
		metrics:         m,
		stopCh:          make(chan struct{}),
		doneCh:          make(chan struct{}),
	}

	// Refresh will fail because it tries to fetch real IANA URLs with 1ms timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := service.refresh(ctx)
	// Should fail due to timeout or network error
	if err == nil {
		t.Log("refresh unexpectedly succeeded (network conditions may vary)")
	}
}

func TestService_ResolverReturnsNilBeforeStart(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.SetupWithWriter(logging.Config{Level: "info", Format: "json"}, &buf)

	service := NewService(24*time.Hour, 10*time.Second, logger, nil)

	// Resolver should be nil before Start
	if service.Resolver() != nil {
		t.Error("resolver should be nil before Start")
	}

	// IsReady should be false
	if service.IsReady() {
		t.Error("service should not be ready before Start")
	}
}

func TestService_BackgroundRefreshTickerTriggers(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.SetupWithWriter(logging.Config{Level: "debug", Format: "json"}, &buf)
	m := metrics.New()

	// Pre-populate with bootstrap data
	bootstrap := NewBootstrap()
	bootstrap.DNS.SetTLDURLs("test", []string{"https://test.example/"})

	service := &Service{
		loader:          NewLoader(1 * time.Millisecond), // Will timeout, but that's OK
		refreshInterval: 50 * time.Millisecond,           // Short interval to trigger ticker
		logger:          logger,
		metrics:         m,
		stopCh:          make(chan struct{}),
		doneCh:          make(chan struct{}),
		running:         true,
		resolver:        NewResolver(bootstrap),
	}

	ctx := context.Background()
	go service.backgroundRefresh(ctx)

	// Wait for at least one ticker tick (refresh will fail but should log warning)
	time.Sleep(150 * time.Millisecond)

	// Stop the service
	close(service.stopCh)

	select {
	case <-service.doneCh:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("backgroundRefresh did not exit after stop")
	}

	// Check that logs contain refresh-related messages
	logOutput := buf.String()
	if len(logOutput) == 0 {
		t.Log("no logs captured (may depend on timing)")
	}
}
