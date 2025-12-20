package cache

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

// setupMiniredis creates a miniredis instance and returns a RedisCache connected to it.
func setupMiniredis(t *testing.T) (*RedisCache, *miniredis.Miniredis) {
	t.Helper()

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}

	cfg := RedisCacheConfig{
		Addr:      mr.Addr(),
		KeyPrefix: "test:",
	}

	cache, err := NewRedisCache(cfg)
	if err != nil {
		mr.Close()
		t.Fatalf("failed to create Redis client: %v", err)
	}

	t.Cleanup(func() {
		_ = cache.Close()
		mr.Close()
	})

	return cache, mr
}

func TestRedisCache_SetAndGet(t *testing.T) {
	cache, _ := setupMiniredis(t)

	ctx := context.Background()
	key := "test:key"
	value := []byte(`{"name": "test"}`)
	ttl := time.Hour

	// Set entry
	err := cache.Set(ctx, key, value, ttl, false)
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

	if entry.Negative {
		t.Error("Get() negative = true, want false")
	}
}

func TestRedisCache_Miss(t *testing.T) {
	cache, _ := setupMiniredis(t)

	ctx := context.Background()

	_, err := cache.Get(ctx, "nonexistent:key")
	if !errors.Is(err, ErrCacheMiss) {
		t.Errorf("Get() error = %v, want %v", err, ErrCacheMiss)
	}
}

func TestRedisCache_Expiration(t *testing.T) {
	cache, mr := setupMiniredis(t)

	ctx := context.Background()
	key := "test:expiring"
	value := []byte("expiring value")
	ttl := time.Second

	// Set entry with TTL
	err := cache.Set(ctx, key, value, ttl, false)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Should be present immediately
	_, err = cache.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get() immediately after Set() error = %v", err)
	}

	// Fast-forward time in miniredis to expire the key
	mr.FastForward(2 * time.Second)

	// Should be expired
	_, err = cache.Get(ctx, key)
	if !errors.Is(err, ErrCacheMiss) {
		t.Errorf("Get() after expiration error = %v, want %v", err, ErrCacheMiss)
	}
}

func TestRedisCache_Delete(t *testing.T) {
	cache, _ := setupMiniredis(t)

	ctx := context.Background()
	key := "test:delete"
	value := []byte("to be deleted")

	// Set entry
	err := cache.Set(ctx, key, value, time.Hour, false)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Verify it exists
	_, err = cache.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get() before Delete() error = %v", err)
	}

	// Delete entry
	err = cache.Delete(ctx, key)
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Should be gone
	_, err = cache.Get(ctx, key)
	if !errors.Is(err, ErrCacheMiss) {
		t.Errorf("Get() after Delete() error = %v, want %v", err, ErrCacheMiss)
	}
}

func TestRedisCache_NegativeCache(t *testing.T) {
	cache, _ := setupMiniredis(t)

	ctx := context.Background()
	key := "test:negative"

	// Set negative cache entry
	err := cache.Set(ctx, key, nil, time.Hour, true)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	entry, err := cache.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if !entry.Negative {
		t.Error("Get() negative = false, want true")
	}
}

func TestRedisCache_Clear(t *testing.T) {
	cache, _ := setupMiniredis(t)

	ctx := context.Background()

	// Add multiple entries
	for i := 0; i < 5; i++ {
		key := "test:clear:" + string(rune('a'+i))
		err := cache.Set(ctx, key, []byte("value"), time.Hour, false)
		if err != nil {
			t.Fatalf("Set() error = %v", err)
		}
	}

	// Clear cache
	err := cache.Clear(ctx)
	if err != nil {
		t.Fatalf("Clear() error = %v", err)
	}

	// Verify entries are gone
	for i := 0; i < 5; i++ {
		key := "test:clear:" + string(rune('a'+i))
		_, err = cache.Get(ctx, key)
		if !errors.Is(err, ErrCacheMiss) {
			t.Errorf("Get(%s) after Clear() error = %v, want %v", key, err, ErrCacheMiss)
		}
	}
}

func TestRedisCache_Stats(t *testing.T) {
	cache, _ := setupMiniredis(t)

	ctx := context.Background()

	_ = cache.Set(ctx, "exists", []byte("value"), time.Hour, false)

	_, _ = cache.Get(ctx, "exists")      // hit
	_, _ = cache.Get(ctx, "exists")      // hit
	_, _ = cache.Get(ctx, "nonexistent") // miss

	stats := cache.Stats()
	if stats.Hits != 2 {
		t.Errorf("Stats.Hits = %d, want 2", stats.Hits)
	}
	if stats.Misses != 1 {
		t.Errorf("Stats.Misses = %d, want 1", stats.Misses)
	}
}

func TestRedisCache_IsAvailable(t *testing.T) {
	cache, _ := setupMiniredis(t)

	ctx := context.Background()

	if !cache.IsAvailable(ctx) {
		t.Error("IsAvailable() = false, want true")
	}
}

func TestRedisCache_IsAvailable_WhenDown(t *testing.T) {
	cache, mr := setupMiniredis(t)

	ctx := context.Background()

	// Verify it's available
	if !cache.IsAvailable(ctx) {
		t.Fatal("IsAvailable() = false, want true (initial)")
	}

	// Close miniredis to simulate Redis going down
	mr.Close()

	// Should no longer be available
	if cache.IsAvailable(ctx) {
		t.Error("IsAvailable() = true after close, want false")
	}
}

func TestDefaultRedisCacheConfig(t *testing.T) {
	cfg := DefaultRedisCacheConfig()

	if cfg.Addr != "localhost:6379" {
		t.Errorf("Addr = %q, want %q", cfg.Addr, "localhost:6379")
	}
	if cfg.DB != 0 {
		t.Errorf("DB = %d, want 0", cfg.DB)
	}
	if cfg.PoolSize != 10 {
		t.Errorf("PoolSize = %d, want 10", cfg.PoolSize)
	}
}

func TestRedisCache_KeyPrefix(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	cfg := RedisCacheConfig{
		Addr:      mr.Addr(),
		KeyPrefix: "myapp:",
	}

	cache, err := NewRedisCache(cfg)
	if err != nil {
		t.Fatalf("NewRedisCache() error = %v", err)
	}
	defer func() { _ = cache.Close() }()

	ctx := context.Background()
	key := "mykey"

	err = cache.Set(ctx, key, []byte("value"), time.Hour, false)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Verify the key is stored with prefix in Redis
	if !mr.Exists("myapp:mykey") {
		t.Error("Key not stored with prefix")
	}

	// Get should work with original key
	entry, err := cache.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if string(entry.Value) != "value" {
		t.Errorf("Get() value = %q, want %q", entry.Value, "value")
	}
}
