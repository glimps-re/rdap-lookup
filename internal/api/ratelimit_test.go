package api

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
)

func TestNewIPRateLimiter(t *testing.T) {
	rl := NewIPRateLimiter(100, 200, nil, nil)
	defer rl.Stop()

	if rl.rate != 100 {
		t.Errorf("expected rate 100, got %v", rl.rate)
	}
	if rl.burst != 200 {
		t.Errorf("expected burst 200, got %d", rl.burst)
	}
}

func TestIPRateLimiter_GetLimiter(t *testing.T) {
	rl := NewIPRateLimiter(10, 20, nil, nil)
	defer rl.Stop()

	// Get limiter for first IP
	limiter1 := rl.getLimiter("192.168.1.1")
	if limiter1 == nil {
		t.Fatal("expected non-nil limiter")
	}

	// Get limiter for same IP should return same instance
	limiter1Again := rl.getLimiter("192.168.1.1")
	if limiter1 != limiter1Again {
		t.Error("expected same limiter instance for same IP")
	}

	// Get limiter for different IP should return different instance
	limiter2 := rl.getLimiter("192.168.1.2")
	if limiter1 == limiter2 {
		t.Error("expected different limiter instance for different IP")
	}
}

func TestIPRateLimiter_RateLimitMiddleware(t *testing.T) {
	// Create rate limiter with very low limit for testing
	rl := NewIPRateLimiter(1, 2, nil, nil) // 1 req/sec, burst of 2
	defer rl.Stop()

	e := echo.New()

	// Create test handler
	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	}

	// Apply middleware
	h := rl.RateLimitMiddleware()(handler)

	// First two requests should succeed (burst = 2)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Real-IP", "10.0.0.1")
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := h(c)
		if err != nil {
			t.Errorf("request %d: unexpected error: %v", i+1, err)
		}
		if rec.Code != http.StatusOK {
			t.Errorf("request %d: expected status 200, got %d", i+1, rec.Code)
		}
	}

	// Third request should be rate limited
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Real-IP", "10.0.0.1")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h(c)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected status 429, got %d", rec.Code)
	}
}

func TestIPRateLimiter_DifferentIPsHaveSeparateLimits(t *testing.T) {
	rl := NewIPRateLimiter(1, 1, nil, nil) // 1 req/sec, burst of 1
	defer rl.Stop()

	e := echo.New()

	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	}

	h := rl.RateLimitMiddleware()(handler)

	// First IP - first request should succeed
	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req1.Header.Set("X-Real-IP", "10.0.0.1")
	rec1 := httptest.NewRecorder()
	c1 := e.NewContext(req1, rec1)

	if err := h(c1); err != nil {
		t.Errorf("IP1 first request: unexpected error: %v", err)
	}
	if rec1.Code != http.StatusOK {
		t.Errorf("IP1 first request: expected status 200, got %d", rec1.Code)
	}

	// First IP - second request should be rate limited
	req1b := httptest.NewRequest(http.MethodGet, "/test", nil)
	req1b.Header.Set("X-Real-IP", "10.0.0.1")
	rec1b := httptest.NewRecorder()
	c1b := e.NewContext(req1b, rec1b)

	if err := h(c1b); err != nil {
		t.Errorf("IP1 second request: unexpected error: %v", err)
	}
	if rec1b.Code != http.StatusTooManyRequests {
		t.Errorf("IP1 second request: expected status 429, got %d", rec1b.Code)
	}

	// Second IP - first request should succeed (different IP has its own limit)
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2.Header.Set("X-Real-IP", "10.0.0.2")
	rec2 := httptest.NewRecorder()
	c2 := e.NewContext(req2, rec2)

	if err := h(c2); err != nil {
		t.Errorf("IP2 first request: unexpected error: %v", err)
	}
	if rec2.Code != http.StatusOK {
		t.Errorf("IP2 first request: expected status 200, got %d", rec2.Code)
	}
}

func TestIPRateLimiter_ConcurrentAccess(t *testing.T) {
	rl := NewIPRateLimiter(1000, 2000, nil, nil)
	defer rl.Stop()

	var wg sync.WaitGroup
	numGoroutines := 100
	requestsPerGoroutine := 100

	// Run concurrent requests from different IPs
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ip := "10.0.0." + string(rune('0'+id%10))
			for j := 0; j < requestsPerGoroutine; j++ {
				limiter := rl.getLimiter(ip)
				_ = limiter.Allow() // Just exercise the limiter
			}
		}(i)
	}

	wg.Wait()
	// Test passes if no race conditions or panics occur
}

func TestIPRateLimiter_Stop(t *testing.T) {
	rl := NewIPRateLimiter(100, 200, nil, nil)

	// Use the limiter
	_ = rl.getLimiter("10.0.0.1")

	// Stop should not panic
	rl.Stop()

	// Give cleanup goroutine time to exit
	time.Sleep(10 * time.Millisecond)
}

func TestIPRateLimiter_ResponseFormat(t *testing.T) {
	rl := NewIPRateLimiter(1, 1, nil, nil) // 1 req/sec, burst of 1
	defer rl.Stop()

	e := echo.New()

	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	}

	h := rl.RateLimitMiddleware()(handler)

	// Exhaust the burst
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Real-IP", "10.0.0.1")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	_ = h(c)

	// Next request should be rate limited with proper response
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2.Header.Set("X-Real-IP", "10.0.0.1")
	rec2 := httptest.NewRecorder()
	c2 := e.NewContext(req2, rec2)

	_ = h(c2)

	if rec2.Code != http.StatusTooManyRequests {
		t.Errorf("expected status 429, got %d", rec2.Code)
	}

	body := rec2.Body.String()
	if body == "" {
		t.Error("expected non-empty response body")
	}

	// Check that response contains expected error structure
	if !contains(body, "RATE_LIMITED") {
		t.Errorf("expected error code RATE_LIMITED in response, got: %s", body)
	}
	if !contains(body, "Too many requests") {
		t.Errorf("expected error message in response, got: %s", body)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestIPRateLimiter_SizeTracking(t *testing.T) {
	rl := NewIPRateLimiter(100, 200, nil, nil)
	defer rl.Stop()

	// Initial size should be 0
	if rl.size.Load() != 0 {
		t.Errorf("initial size = %d, want 0", rl.size.Load())
	}

	// Add a few limiters
	_ = rl.getLimiter("10.0.0.1")
	_ = rl.getLimiter("10.0.0.2")
	_ = rl.getLimiter("10.0.0.3")

	if rl.size.Load() != 3 {
		t.Errorf("size after 3 IPs = %d, want 3", rl.size.Load())
	}

	// Getting existing limiter shouldn't increase size
	_ = rl.getLimiter("10.0.0.1")
	if rl.size.Load() != 3 {
		t.Errorf("size after getting existing IP = %d, want 3", rl.size.Load())
	}
}

func TestIPRateLimiter_SubnetFallbackAtCapacity(t *testing.T) {
	rl := NewIPRateLimiter(100, 200, nil, nil)
	defer rl.Stop()

	// Manually set size to max to simulate capacity
	rl.size.Store(maxRateLimiterEntries)

	// New IP should get subnet limiter (fallback), not nil
	limiter := rl.getLimiter("192.168.1.100")
	if limiter == nil {
		t.Error("expected subnet limiter when at IP capacity")
	}

	// Same subnet should get same limiter
	limiter2 := rl.getLimiter("192.168.1.200")
	if limiter2 == nil {
		t.Error("expected subnet limiter for same subnet")
	}

	// Subnet size should increase
	if rl.subnetSize.Load() != 1 {
		t.Errorf("expected subnetSize 1, got %d", rl.subnetSize.Load())
	}

	// Existing IPs should still work (we need to add one first before capacity check)
	rl.size.Store(0) // Reset to add one
	_ = rl.getLimiter("10.0.0.1")
	rl.size.Store(maxRateLimiterEntries) // Set to capacity again

	// Existing IP should still return its limiter
	limiter = rl.getLimiter("10.0.0.1")
	if limiter == nil {
		t.Error("expected non-nil limiter for existing IP at capacity")
	}
}

func TestIPRateLimiter_NilLimiterOnlyWhenBothAtCapacity(t *testing.T) {
	rl := NewIPRateLimiter(100, 200, nil, nil)
	defer rl.Stop()

	// Set both IP and subnet maps to capacity
	rl.size.Store(maxRateLimiterEntries)
	rl.subnetSize.Store(maxSubnetLimiterEntries)

	// New IP should get nil limiter only when both are at capacity
	limiter := rl.getLimiter("new-ip")
	if limiter != nil {
		t.Error("expected nil limiter when both IP and subnet at capacity")
	}
}

func TestIPRateLimiter_MiddlewareWithSubnetFallback(t *testing.T) {
	rl := NewIPRateLimiter(100, 200, nil, nil)
	defer rl.Stop()

	e := echo.New()

	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	}

	h := rl.RateLimitMiddleware()(handler)

	// Set IP map to capacity but subnet map still has room
	rl.size.Store(maxRateLimiterEntries)

	// Request from new IP should succeed using subnet limiter
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Real-IP", "192.168.1.100")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h(c)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200 with subnet fallback, got %d", rec.Code)
	}
}

func TestIPRateLimiter_MiddlewareFailClosedWhenBothAtCapacity(t *testing.T) {
	rl := NewIPRateLimiter(100, 200, nil, nil)
	defer rl.Stop()

	e := echo.New()

	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	}

	h := rl.RateLimitMiddleware()(handler)

	// Set both maps to capacity
	rl.size.Store(maxRateLimiterEntries)
	rl.subnetSize.Store(maxSubnetLimiterEntries)

	// Request from new IP should be rate limited (true fail-closed)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Real-IP", "new-ip-at-capacity")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := h(c)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected status 429 when both at capacity, got %d", rec.Code)
	}
}

func TestIPRateLimiter_CleanupRemovesStaleEntries(t *testing.T) {
	// Create a rate limiter with a very short cleanup interval for testing
	rl := &IPRateLimiter{
		rate:  100,
		burst: 200,
		done:  make(chan struct{}),
	}

	// Don't start the cleanup goroutine - we'll call it manually

	// Add an entry with old last access time
	staleEntry := &rateLimiterEntry{
		limiter:    nil,                               // Not used in this test
		lastAccess: time.Now().Add(-15 * time.Minute), // 15 minutes ago (stale)
	}
	rl.limiters.Store("stale-ip", staleEntry)
	rl.size.Store(1)

	// Add an entry with recent last access time
	recentEntry := &rateLimiterEntry{
		limiter:    nil,
		lastAccess: time.Now(), // Just now (not stale)
	}
	rl.limiters.Store("recent-ip", recentEntry)
	rl.size.Add(1)

	if rl.size.Load() != 2 {
		t.Fatalf("initial size = %d, want 2", rl.size.Load())
	}

	// Simulate the cleanup logic
	const maxAge = 10 * time.Minute
	now := time.Now()
	rl.limiters.Range(func(key, value any) bool {
		entry := value.(*rateLimiterEntry)
		entry.mu.Lock()
		age := now.Sub(entry.lastAccess)
		entry.mu.Unlock()

		if age > maxAge {
			rl.limiters.Delete(key)
			rl.size.Add(-1)
		}
		return true
	})

	// Stale entry should be removed
	if rl.size.Load() != 1 {
		t.Errorf("size after cleanup = %d, want 1", rl.size.Load())
	}

	// Check that the right entry was removed
	if _, ok := rl.limiters.Load("stale-ip"); ok {
		t.Error("stale-ip should have been removed")
	}
	if _, ok := rl.limiters.Load("recent-ip"); !ok {
		t.Error("recent-ip should still exist")
	}
}

func TestIPRateLimiter_LastAccessUpdated(t *testing.T) {
	rl := NewIPRateLimiter(100, 200, nil, nil)
	defer rl.Stop()

	// Get limiter to create entry
	_ = rl.getLimiter("test-ip")

	// Get the entry
	val, ok := rl.limiters.Load("test-ip")
	if !ok {
		t.Fatal("entry not found")
	}
	entry := val.(*rateLimiterEntry)
	entry.mu.Lock()
	firstAccess := entry.lastAccess
	entry.mu.Unlock()

	// Wait a bit
	time.Sleep(10 * time.Millisecond)

	// Access again
	_ = rl.getLimiter("test-ip")

	// Check that last access was updated
	entry.mu.Lock()
	secondAccess := entry.lastAccess
	entry.mu.Unlock()

	if !secondAccess.After(firstAccess) {
		t.Error("lastAccess should have been updated")
	}
}

func TestIPRateLimiter_CleanupLoopWithTicker(t *testing.T) {
	// Create a rate limiter with custom short cleanup interval
	rl := &IPRateLimiter{
		rate:  100,
		burst: 200,
		done:  make(chan struct{}),
	}

	// Use a very short ticker for testing
	rl.cleanup = time.NewTicker(50 * time.Millisecond)

	// Start cleanup loop in background
	go rl.cleanupLoop()

	// Add an entry with old last access time
	staleEntry := &rateLimiterEntry{
		limiter:    nil,
		lastAccess: time.Now().Add(-15 * time.Minute),
	}
	rl.limiters.Store("stale-ip-ticker", staleEntry)
	rl.size.Store(1)

	// Wait for cleanup to run
	time.Sleep(100 * time.Millisecond)

	// Stop the loop
	rl.Stop()

	// Stale entry should have been removed by cleanup loop
	if _, ok := rl.limiters.Load("stale-ip-ticker"); ok {
		t.Error("stale entry should have been removed by cleanup loop")
	}

	if rl.size.Load() != 0 {
		t.Errorf("size should be 0 after cleanup, got %d", rl.size.Load())
	}
}

func TestIPRateLimiter_CleanupLoopStopsOnDone(t *testing.T) {
	rl := &IPRateLimiter{
		rate:    100,
		burst:   200,
		done:    make(chan struct{}),
		cleanup: time.NewTicker(1 * time.Hour), // Long ticker, won't fire
	}

	cleanupExited := make(chan struct{})
	go func() {
		rl.cleanupLoop()
		close(cleanupExited)
	}()

	// Give goroutine time to start
	time.Sleep(10 * time.Millisecond)

	// Stop the rate limiter
	rl.Stop()

	// cleanupLoop should exit
	select {
	case <-cleanupExited:
		// Success
	case <-time.After(1 * time.Second):
		t.Error("cleanupLoop did not exit after Stop()")
	}
}
