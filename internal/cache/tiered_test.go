package cache

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func TestNewTieredCache(t *testing.T) {
	cfg := DefaultTieredCacheConfig()
	cache, err := NewTieredCache(cfg)
	if err != nil {
		t.Fatalf("NewTieredCache() error = %v", err)
	}
	t.Cleanup(func() { _ = cache.Close() })

	if cache.L1() == nil {
		t.Error("L1 cache is nil")
	}
	if cache.L2() != nil {
		t.Error("L2 cache should be nil when not configured")
	}
}

func TestTieredCache_L1Only_SetAndGet(t *testing.T) {
	cfg := DefaultTieredCacheConfig()
	cache, err := NewTieredCache(cfg)
	if err != nil {
		t.Fatalf("NewTieredCache() error = %v", err)
	}
	t.Cleanup(func() { _ = cache.Close() })

	ctx := context.Background()
	key := "test:key"
	value := []byte(`{"name": "test"}`)
	ttl := time.Hour

	// Set entry
	err = cache.Set(ctx, key, value, ttl, false)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Get entry
	entry, err := cache.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if string(entry.Value) != string(value) {
		t.Errorf("Get() value = %q, want %q", entry.Value, value)
	}
}

func TestTieredCache_L1Only_Miss(t *testing.T) {
	cfg := DefaultTieredCacheConfig()
	cache, err := NewTieredCache(cfg)
	if err != nil {
		t.Fatalf("NewTieredCache() error = %v", err)
	}
	t.Cleanup(func() { _ = cache.Close() })

	ctx := context.Background()

	_, err = cache.Get(ctx, "nonexistent")
	if !errors.Is(err, ErrCacheMiss) {
		t.Errorf("Get() error = %v, want %v", err, ErrCacheMiss)
	}
}

func TestTieredCache_L1Only_Delete(t *testing.T) {
	cfg := DefaultTieredCacheConfig()
	cache, err := NewTieredCache(cfg)
	if err != nil {
		t.Fatalf("NewTieredCache() error = %v", err)
	}
	t.Cleanup(func() { _ = cache.Close() })

	ctx := context.Background()
	key := "test:delete"

	_ = cache.Set(ctx, key, []byte("value"), time.Hour, false)

	err = cache.Delete(ctx, key)
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	_, err = cache.Get(ctx, key)
	if !errors.Is(err, ErrCacheMiss) {
		t.Errorf("Get() after Delete() error = %v, want %v", err, ErrCacheMiss)
	}
}

func TestTieredCache_L1Only_Clear(t *testing.T) {
	cfg := DefaultTieredCacheConfig()
	cache, err := NewTieredCache(cfg)
	if err != nil {
		t.Fatalf("NewTieredCache() error = %v", err)
	}
	t.Cleanup(func() { _ = cache.Close() })

	ctx := context.Background()

	// Add entries
	for i := range 5 {
		key := "test:clear:" + string(rune('a'+i))
		_ = cache.Set(ctx, key, []byte("value"), time.Hour, false)
	}

	err = cache.Clear(ctx)
	if err != nil {
		t.Fatalf("Clear() error = %v", err)
	}

	// Verify entries are gone
	for i := range 5 {
		key := "test:clear:" + string(rune('a'+i))
		_, err = cache.Get(ctx, key)
		if !errors.Is(err, ErrCacheMiss) {
			t.Errorf("Get(%s) after Clear() error = %v, want %v", key, err, ErrCacheMiss)
		}
	}
}

func TestTieredCache_SetWithDefaultTTL(t *testing.T) {
	cfg := DefaultTieredCacheConfig()
	cfg.DefaultTTL = time.Hour
	cfg.NegativeTTL = time.Minute

	cache, err := NewTieredCache(cfg)
	if err != nil {
		t.Fatalf("NewTieredCache() error = %v", err)
	}
	t.Cleanup(func() { _ = cache.Close() })

	ctx := context.Background()

	// Positive entry
	err = cache.SetWithDefaultTTL(ctx, "positive", []byte("value"), false)
	if err != nil {
		t.Fatalf("SetWithDefaultTTL() error = %v", err)
	}

	// Negative entry
	err = cache.SetWithDefaultTTL(ctx, "negative", nil, true)
	if err != nil {
		t.Fatalf("SetWithDefaultTTL() error = %v", err)
	}

	// Verify both exist
	_, err = cache.Get(ctx, "positive")
	if err != nil {
		t.Errorf("Get(positive) error = %v", err)
	}

	entry, err := cache.Get(ctx, "negative")
	if err != nil {
		t.Errorf("Get(negative) error = %v", err)
	}
	if !entry.Negative {
		t.Error("Negative entry should have Negative=true")
	}
}

func TestTieredCache_Stats(t *testing.T) {
	cfg := DefaultTieredCacheConfig()
	cache, err := NewTieredCache(cfg)
	if err != nil {
		t.Fatalf("NewTieredCache() error = %v", err)
	}
	t.Cleanup(func() { _ = cache.Close() })

	ctx := context.Background()

	_ = cache.Set(ctx, "key", []byte("value"), time.Hour, false)
	_, _ = cache.Get(ctx, "key")
	_, _ = cache.Get(ctx, "nonexistent")

	stats := cache.Stats()
	if stats.L1.Hits != 1 {
		t.Errorf("L1.Hits = %d, want 1", stats.L1.Hits)
	}
	if stats.L1.Misses != 1 {
		t.Errorf("L1.Misses = %d, want 1", stats.L1.Misses)
	}
	if stats.L2 != nil {
		t.Error("L2 stats should be nil when L2 is not configured")
	}
}

func TestTieredCache_GetOrFetch(t *testing.T) {
	cfg := DefaultTieredCacheConfig()
	cache, err := NewTieredCache(cfg)
	if err != nil {
		t.Fatalf("NewTieredCache() error = %v", err)
	}
	t.Cleanup(func() { _ = cache.Close() })

	ctx := context.Background()
	fetchCount := 0

	fetch := func(_ context.Context) ([]byte, error) {
		fetchCount++
		return []byte("fetched value"), nil
	}

	// First call should fetch
	value, cached, err := cache.GetOrFetch(ctx, "key", fetch)
	if err != nil {
		t.Fatalf("GetOrFetch() error = %v", err)
	}
	if cached {
		t.Error("First call should not be cached")
	}
	if string(value) != "fetched value" {
		t.Errorf("Value = %q, want %q", value, "fetched value")
	}
	if fetchCount != 1 {
		t.Errorf("fetchCount = %d, want 1", fetchCount)
	}

	// Second call should be cached
	_, cached, err = cache.GetOrFetch(ctx, "key", fetch)
	if err != nil {
		t.Fatalf("GetOrFetch() error = %v", err)
	}
	if !cached {
		t.Error("Second call should be cached")
	}
	if fetchCount != 1 {
		t.Errorf("fetchCount = %d, want 1 (should not have fetched again)", fetchCount)
	}
}

func TestTieredCache_GetOrFetch_Singleflight(t *testing.T) {
	cfg := DefaultTieredCacheConfig()
	cache, err := NewTieredCache(cfg)
	if err != nil {
		t.Fatalf("NewTieredCache() error = %v", err)
	}
	t.Cleanup(func() { _ = cache.Close() })

	ctx := context.Background()
	var fetchCount atomic.Int32

	fetch := func(_ context.Context) ([]byte, error) {
		fetchCount.Add(1)
		time.Sleep(50 * time.Millisecond) // Simulate slow fetch
		return []byte("fetched"), nil
	}

	// Launch multiple concurrent fetches for the same key
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = cache.GetOrFetch(ctx, "concurrent-key", fetch)
		}()
	}
	wg.Wait()

	// Should only fetch once due to singleflight
	if fetchCount.Load() != 1 {
		t.Errorf("fetchCount = %d, want 1 (singleflight should deduplicate)", fetchCount.Load())
	}
}

func TestTieredCache_GetOrFetchWithNegative(t *testing.T) {
	cfg := DefaultTieredCacheConfig()
	cache, err := NewTieredCache(cfg)
	if err != nil {
		t.Fatalf("NewTieredCache() error = %v", err)
	}
	t.Cleanup(func() { _ = cache.Close() })

	ctx := context.Background()
	notFoundErr := errors.New("not found")
	fetchCount := 0

	fetch := func(_ context.Context) ([]byte, error) {
		fetchCount++
		return nil, notFoundErr
	}

	// First call should fetch and cache negative
	_, cached, err := cache.GetOrFetchWithNegative(ctx, "missing", fetch, notFoundErr)
	if !errors.Is(err, notFoundErr) {
		t.Fatalf("GetOrFetchWithNegative() error = %v, want %v", err, notFoundErr)
	}
	if cached {
		t.Error("First call should not be cached")
	}
	if fetchCount != 1 {
		t.Errorf("fetchCount = %d, want 1", fetchCount)
	}

	// Second call should hit negative cache
	_, cached, err = cache.GetOrFetchWithNegative(ctx, "missing", fetch, notFoundErr)
	if !errors.Is(err, notFoundErr) {
		t.Fatalf("GetOrFetchWithNegative() error = %v, want %v", err, notFoundErr)
	}
	if !cached {
		t.Error("Second call should be cached (negative)")
	}
	if fetchCount != 1 {
		t.Errorf("fetchCount = %d, want 1 (should not fetch again)", fetchCount)
	}
}

func TestTieredCache_HasL2(t *testing.T) {
	// Without L2
	cfg := DefaultTieredCacheConfig()
	cache, _ := NewTieredCache(cfg)
	t.Cleanup(func() { _ = cache.Close() })

	if cache.HasL2() {
		t.Error("HasL2() = true, want false")
	}
	if cache.L2() != nil {
		t.Error("L2() should be nil")
	}
	if cache.L1() == nil {
		t.Error("L1() should not be nil")
	}
}

func TestDefaultTieredCacheConfig(t *testing.T) {
	cfg := DefaultTieredCacheConfig()

	if cfg.DefaultTTL != 24*time.Hour {
		t.Errorf("DefaultTTL = %v, want 24h", cfg.DefaultTTL)
	}
	if cfg.NegativeTTL != 1*time.Hour {
		t.Errorf("NegativeTTL = %v, want 1h", cfg.NegativeTTL)
	}
	if cfg.L2Config != nil {
		t.Error("L2Config should be nil by default")
	}
	if cfg.FetchTimeout != 30*time.Second {
		t.Errorf("FetchTimeout = %v, want 30s", cfg.FetchTimeout)
	}
}

// setupTieredWithL2 creates a tiered cache with miniredis as L2.
func setupTieredWithL2(t *testing.T) (*TieredCache, *miniredis.Miniredis) {
	t.Helper()

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}

	l1, err := NewMemoryCache(DefaultMemoryCacheConfig())
	if err != nil {
		mr.Close()
		t.Fatalf("failed to create L1 cache: %v", err)
	}

	l2, err := NewRedisCache(RedisCacheConfig{
		Addr:      mr.Addr(),
		KeyPrefix: "test:",
	})
	if err != nil {
		_ = l1.Close()
		mr.Close()
		t.Fatalf("failed to create L2 cache: %v", err)
	}

	cfg := TieredCacheConfig{
		DefaultTTL:     time.Hour,
		NegativeTTL:    10 * time.Minute,
		L1PromotionTTL: 5 * time.Minute,
		EnableL2Writes: true,
	}

	tc := NewTieredCacheWithBackends(l1, l2, cfg)

	t.Cleanup(func() {
		_ = tc.Close()
		mr.Close()
	})

	return tc, mr
}

func TestTieredCache_WithL2_SetAndGet(t *testing.T) {
	tc, _ := setupTieredWithL2(t)

	ctx := context.Background()
	key := "test:key"
	value := []byte(`{"name": "test"}`)

	// Set entry
	err := tc.Set(ctx, key, value, time.Hour, false)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Get entry (should hit L1)
	entry, err := tc.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if string(entry.Value) != string(value) {
		t.Errorf("Get() value = %q, want %q", entry.Value, value)
	}
}

func TestTieredCache_WithL2_L2Promotion(t *testing.T) {
	tc, _ := setupTieredWithL2(t)

	ctx := context.Background()
	key := "test:promote"
	value := []byte("promote me")

	// Set entry
	err := tc.Set(ctx, key, value, time.Hour, false)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Clear L1 to force L2 lookup
	_ = tc.L1().Clear(ctx)

	// Get should hit L2 and promote to L1
	entry, err := tc.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get() after L1 clear error = %v", err)
	}

	if string(entry.Value) != string(value) {
		t.Errorf("Get() value = %q, want %q", entry.Value, value)
	}

	// Now L1 should have the entry (promoted from L2)
	entry, err = tc.L1().Get(ctx, key)
	if err != nil {
		t.Fatalf("L1.Get() after promotion error = %v", err)
	}

	if string(entry.Value) != string(value) {
		t.Errorf("L1 promoted value = %q, want %q", entry.Value, value)
	}
}

func TestTieredCache_WithL2_Stats(t *testing.T) {
	tc, _ := setupTieredWithL2(t)

	ctx := context.Background()

	// Set entry
	_ = tc.Set(ctx, "key", []byte("value"), time.Hour, false)

	// Get from L1 (hit)
	_, _ = tc.Get(ctx, "key")

	// Clear L1
	_ = tc.L1().Clear(ctx)

	// Get from L2 (L1 miss, L2 hit)
	_, _ = tc.Get(ctx, "key")

	stats := tc.Stats()

	if stats.L2 == nil {
		t.Fatal("L2 stats should not be nil")
	}

	if !stats.L2Available {
		t.Error("L2Available = false, want true")
	}
}

func TestTieredCache_WithL2_Delete(t *testing.T) {
	tc, _ := setupTieredWithL2(t)

	ctx := context.Background()
	key := "test:delete"

	// Set entry
	_ = tc.Set(ctx, key, []byte("value"), time.Hour, false)

	// Delete should remove from both L1 and L2
	err := tc.Delete(ctx, key)
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Should be gone from L1
	_, err = tc.L1().Get(ctx, key)
	if !errors.Is(err, ErrCacheMiss) {
		t.Errorf("L1.Get() after Delete() error = %v, want %v", err, ErrCacheMiss)
	}

	// Should be gone from L2
	_, err = tc.L2().Get(ctx, key)
	if !errors.Is(err, ErrCacheMiss) {
		t.Errorf("L2.Get() after Delete() error = %v, want %v", err, ErrCacheMiss)
	}
}

func TestTieredCache_WithL2_Clear(t *testing.T) {
	tc, _ := setupTieredWithL2(t)

	ctx := context.Background()

	// Add entries
	for i := range 5 {
		key := "test:clear:" + string(rune('a'+i))
		_ = tc.Set(ctx, key, []byte("value"), time.Hour, false)
	}

	// Clear should remove from both tiers
	err := tc.Clear(ctx)
	if err != nil {
		t.Fatalf("Clear() error = %v", err)
	}

	// Verify entries are gone from both
	for i := range 5 {
		key := "test:clear:" + string(rune('a'+i))
		_, err = tc.Get(ctx, key)
		if !errors.Is(err, ErrCacheMiss) {
			t.Errorf("Get(%s) after Clear() error = %v, want %v", key, err, ErrCacheMiss)
		}
	}
}

func TestNewTieredCacheWithBackends(t *testing.T) {
	l1, _ := NewMemoryCache(DefaultMemoryCacheConfig())
	defer func() { _ = l1.Close() }()

	cfg := TieredCacheConfig{
		DefaultTTL:   time.Hour,
		NegativeTTL:  time.Minute,
		FetchTimeout: 30 * time.Second,
	}

	// Test with nil L2
	tc := NewTieredCacheWithBackends(l1, nil, cfg)
	if tc.L1() == nil {
		t.Error("L1() should not be nil")
	}
	if tc.L2() != nil {
		t.Error("L2() should be nil")
	}
	if tc.HasL2() {
		t.Error("HasL2() should be false")
	}
}

// TestTieredCache_GetOrFetch_JoinedCallersSurviveFirstCallerCancel verifies that
// when multiple goroutines join a singleflight for the same key, cancelling the
// first caller's context does not abort the flight for all joined callers.
func TestTieredCache_GetOrFetch_JoinedCallersSurviveFirstCallerCancel(t *testing.T) {
	cfg := DefaultTieredCacheConfig()
	cfg.FetchTimeout = 5 * time.Second
	c, err := NewTieredCache(cfg)
	if err != nil {
		t.Fatalf("NewTieredCache() error = %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	fetchStarted := make(chan struct{})
	fetchUnblock := make(chan struct{})

	fetch := func(_ context.Context) ([]byte, error) {
		close(fetchStarted)
		<-fetchUnblock
		return []byte("result"), nil
	}

	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2 := context.Background()

	var wg sync.WaitGroup
	var val1 []byte
	var err1 error
	var val2 []byte
	var err2 error

	// First caller starts the flight.
	wg.Add(1)
	go func() {
		defer wg.Done()
		val1, _, err1 = c.GetOrFetch(ctx1, "shared-key", fetch)
	}()

	// Wait until the fetch goroutine is running, then cancel ctx1.
	<-fetchStarted
	cancel1()

	// Second caller joins the in-flight request.
	wg.Add(1)
	go func() {
		defer wg.Done()
		val2, _, err2 = c.GetOrFetch(ctx2, "shared-key", fetch)
	}()

	// Unblock the fetch so both callers can receive the result.
	close(fetchUnblock)
	wg.Wait()

	// The fetch context is detached, so it should complete successfully.
	// Both val1 and val2 should either have the result or an error —
	// but val2 must never fail because ctx2 is still valid.
	if err2 != nil {
		t.Errorf("joined caller got error despite valid ctx: %v", err2)
	}
	if string(val2) != "result" {
		t.Errorf("joined caller got value = %q, want %q", val2, "result")
	}

	// val1 may be "" if ctx1 was cancelled before the result was available,
	// but the flight still ran so either the result or an error is acceptable.
	_ = val1
	_ = err1
}

// TestTieredCache_GetOrFetch_FetchTimeoutBoundsUnresponsiveFetch verifies that
// FetchTimeout independently limits an unresponsive fetch even when the caller
// context has no deadline.
func TestTieredCache_GetOrFetch_FetchTimeoutBoundsUnresponsiveFetch(t *testing.T) {
	cfg := DefaultTieredCacheConfig()
	cfg.FetchTimeout = 50 * time.Millisecond // Very short for testing
	c, err := NewTieredCache(cfg)
	if err != nil {
		t.Fatalf("NewTieredCache() error = %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	// fetch blocks until its context is cancelled.
	fetch := func(fc context.Context) ([]byte, error) {
		<-fc.Done()
		return nil, fc.Err()
	}

	start := time.Now()
	_, _, fetchErr := c.GetOrFetch(context.Background(), "blocked-key", fetch)
	elapsed := time.Since(start)

	// Should have returned within a reasonable window around FetchTimeout.
	if fetchErr == nil {
		t.Error("expected error from timed-out fetch, got nil")
	}
	if elapsed > 2*time.Second {
		t.Errorf("fetch took %v, want <= 2s (FetchTimeout = 50ms)", elapsed)
	}
}

// TestTieredCache_GetOrFetchWithNegative_FlightDetachedFromCallerCtx mirrors
// TestTieredCache_GetOrFetch_JoinedCallersSurviveFirstCallerCancel for the
// negative-caching variant.
func TestTieredCache_GetOrFetchWithNegative_FlightDetachedFromCallerCtx(t *testing.T) {
	cfg := DefaultTieredCacheConfig()
	cfg.FetchTimeout = 5 * time.Second
	c, err := NewTieredCache(cfg)
	if err != nil {
		t.Fatalf("NewTieredCache() error = %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	notFoundErr := errors.New("not found")
	fetchStarted := make(chan struct{})
	fetchUnblock := make(chan struct{})

	fetch := func(_ context.Context) ([]byte, error) {
		close(fetchStarted)
		<-fetchUnblock
		return []byte("data"), nil
	}

	ctx1, cancel1 := context.WithCancel(context.Background())
	ctx2 := context.Background()

	var wg sync.WaitGroup
	var err2 error
	var val2 []byte

	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _, _ = c.GetOrFetchWithNegative(ctx1, "shared-neg-key", fetch, notFoundErr)
	}()

	<-fetchStarted
	cancel1()

	wg.Add(1)
	go func() {
		defer wg.Done()
		val2, _, err2 = c.GetOrFetchWithNegative(ctx2, "shared-neg-key", fetch, notFoundErr)
	}()

	close(fetchUnblock)
	wg.Wait()

	if err2 != nil {
		t.Errorf("joined caller got error: %v", err2)
	}
	if string(val2) != "data" {
		t.Errorf("joined caller got value = %q, want %q", val2, "data")
	}
}
