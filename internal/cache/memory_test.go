package cache

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNewMemoryCache(t *testing.T) {
	cfg := DefaultMemoryCacheConfig()
	cache, err := NewMemoryCache(cfg)
	if err != nil {
		t.Fatalf("NewMemoryCache() error = %v", err)
	}
	t.Cleanup(func() { _ = cache.Close() })

	if cache == nil {
		t.Fatal("NewMemoryCache() returned nil")
	}
}

func TestMemoryCache_SetAndGet(t *testing.T) {
	cache, err := NewMemoryCache(DefaultMemoryCacheConfig())
	if err != nil {
		t.Fatalf("NewMemoryCache() error = %v", err)
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

	if entry.Key != key {
		t.Errorf("Get() key = %q, want %q", entry.Key, key)
	}

	if entry.Negative {
		t.Error("Get() negative = true, want false")
	}
}

func TestMemoryCache_Miss(t *testing.T) {
	cache, err := NewMemoryCache(DefaultMemoryCacheConfig())
	if err != nil {
		t.Fatalf("NewMemoryCache() error = %v", err)
	}
	t.Cleanup(func() { _ = cache.Close() })

	ctx := context.Background()

	_, err = cache.Get(ctx, "nonexistent")
	if !errors.Is(err, ErrCacheMiss) {
		t.Errorf("Get() error = %v, want %v", err, ErrCacheMiss)
	}
}

func TestMemoryCache_Expiration(t *testing.T) {
	cache, err := NewMemoryCache(DefaultMemoryCacheConfig())
	if err != nil {
		t.Fatalf("NewMemoryCache() error = %v", err)
	}
	t.Cleanup(func() { _ = cache.Close() })

	ctx := context.Background()
	key := "test:expiring"
	value := []byte("expiring value")
	ttl := 50 * time.Millisecond

	// Set entry with short TTL
	err = cache.Set(ctx, key, value, ttl, false)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	// Should be present immediately
	_, err = cache.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get() immediately after Set() error = %v", err)
	}

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Should be expired
	_, err = cache.Get(ctx, key)
	if !errors.Is(err, ErrCacheMiss) {
		t.Errorf("Get() after expiration error = %v, want %v", err, ErrCacheMiss)
	}
}

func TestMemoryCache_Delete(t *testing.T) {
	cache, err := NewMemoryCache(DefaultMemoryCacheConfig())
	if err != nil {
		t.Fatalf("NewMemoryCache() error = %v", err)
	}
	t.Cleanup(func() { _ = cache.Close() })

	ctx := context.Background()
	key := "test:delete"
	value := []byte("to be deleted")

	// Set entry
	err = cache.Set(ctx, key, value, time.Hour, false)
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

func TestMemoryCache_Clear(t *testing.T) {
	cache, err := NewMemoryCache(DefaultMemoryCacheConfig())
	if err != nil {
		t.Fatalf("NewMemoryCache() error = %v", err)
	}
	t.Cleanup(func() { _ = cache.Close() })

	ctx := context.Background()

	// Add multiple entries
	for i := range 10 {
		key := "test:clear:" + string(rune('a'+i))
		err := cache.Set(ctx, key, []byte("value"), time.Hour, false)
		if err != nil {
			t.Fatalf("Set() error = %v", err)
		}
	}

	if cache.Len() != 10 {
		t.Errorf("Len() = %d, want 10", cache.Len())
	}

	// Clear cache
	err = cache.Clear(ctx)
	if err != nil {
		t.Fatalf("Clear() error = %v", err)
	}

	if cache.Len() != 0 {
		t.Errorf("Len() after Clear() = %d, want 0", cache.Len())
	}
}

func TestMemoryCache_NegativeCache(t *testing.T) {
	cache, err := NewMemoryCache(DefaultMemoryCacheConfig())
	if err != nil {
		t.Fatalf("NewMemoryCache() error = %v", err)
	}
	t.Cleanup(func() { _ = cache.Close() })

	ctx := context.Background()
	key := "test:negative"

	// Set negative cache entry
	err = cache.Set(ctx, key, nil, time.Hour, true)
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

func TestMemoryCache_Stats(t *testing.T) {
	cache, err := NewMemoryCache(DefaultMemoryCacheConfig())
	if err != nil {
		t.Fatalf("NewMemoryCache() error = %v", err)
	}
	t.Cleanup(func() { _ = cache.Close() })

	ctx := context.Background()

	// Initial stats
	stats := cache.Stats()
	if stats.Hits != 0 || stats.Misses != 0 {
		t.Errorf("Initial stats: hits=%d, misses=%d, want 0, 0", stats.Hits, stats.Misses)
	}

	// Generate some hits and misses
	_ = cache.Set(ctx, "exists", []byte("value"), time.Hour, false)

	_, _ = cache.Get(ctx, "exists")      // hit
	_, _ = cache.Get(ctx, "exists")      // hit
	_, _ = cache.Get(ctx, "nonexistent") // miss

	stats = cache.Stats()
	if stats.Hits != 2 {
		t.Errorf("Stats.Hits = %d, want 2", stats.Hits)
	}
	if stats.Misses != 1 {
		t.Errorf("Stats.Misses = %d, want 1", stats.Misses)
	}
	if stats.Entries != 1 {
		t.Errorf("Stats.Entries = %d, want 1", stats.Entries)
	}
}

func TestMemoryCache_SizeLimit(t *testing.T) {
	cfg := MemoryCacheConfig{
		MaxEntries: 1000,
		MaxSize:    100, // 100 bytes max
	}
	cache, err := NewMemoryCache(cfg)
	if err != nil {
		t.Fatalf("NewMemoryCache() error = %v", err)
	}
	t.Cleanup(func() { _ = cache.Close() })

	ctx := context.Background()

	// Add entries that exceed size limit
	for i := range 10 {
		key := "test:size:" + string(rune('a'+i))
		value := make([]byte, 20) // 20 bytes each
		err := cache.Set(ctx, key, value, time.Hour, false)
		if err != nil {
			t.Fatalf("Set() error = %v", err)
		}
	}

	// Should have evicted some entries to stay under limit
	stats := cache.Stats()
	if stats.SizeBytes > 100 {
		t.Errorf("Stats.SizeBytes = %d, want <= 100", stats.SizeBytes)
	}
	if stats.Evictions == 0 {
		t.Error("Stats.Evictions = 0, want > 0")
	}
}

func TestMemoryCache_LRUEviction(t *testing.T) {
	cfg := MemoryCacheConfig{
		MaxEntries: 3,
		MaxSize:    0, // No size limit
	}
	cache, err := NewMemoryCache(cfg)
	if err != nil {
		t.Fatalf("NewMemoryCache() error = %v", err)
	}
	t.Cleanup(func() { _ = cache.Close() })

	ctx := context.Background()

	// Add 3 entries
	_ = cache.Set(ctx, "a", []byte("1"), time.Hour, false)
	_ = cache.Set(ctx, "b", []byte("2"), time.Hour, false)
	_ = cache.Set(ctx, "c", []byte("3"), time.Hour, false)

	// Access "a" to make it recently used
	_, _ = cache.Get(ctx, "a")

	// Add 4th entry, should evict "b" (least recently used)
	_ = cache.Set(ctx, "d", []byte("4"), time.Hour, false)

	// "b" should be evicted
	_, err = cache.Get(ctx, "b")
	if !errors.Is(err, ErrCacheMiss) {
		t.Errorf("Get(b) after eviction error = %v, want %v", err, ErrCacheMiss)
	}

	// "a", "c", "d" should still exist
	for _, key := range []string{"a", "c", "d"} {
		_, err = cache.Get(ctx, key)
		if err != nil {
			t.Errorf("Get(%s) error = %v, want nil", key, err)
		}
	}
}

func TestEntry_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{
			name:      "not expired",
			expiresAt: time.Now().Add(time.Hour),
			want:      false,
		},
		{
			name:      "expired",
			expiresAt: time.Now().Add(-time.Hour),
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Entry{ExpiresAt: tt.expiresAt}
			if got := e.IsExpired(); got != tt.want {
				t.Errorf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEntry_TTL(t *testing.T) {
	// Future expiration
	e := &Entry{ExpiresAt: time.Now().Add(time.Hour)}
	ttl := e.TTL()
	if ttl < 59*time.Minute || ttl > time.Hour {
		t.Errorf("TTL() = %v, want ~1 hour", ttl)
	}

	// Past expiration
	e = &Entry{ExpiresAt: time.Now().Add(-time.Hour)}
	ttl = e.TTL()
	if ttl != 0 {
		t.Errorf("TTL() for expired = %v, want 0", ttl)
	}
}

func TestBuildKey(t *testing.T) {
	tests := []struct {
		prefix string
		value  string
		want   string
	}{
		{KeyPrefixDomain, "example.com", "rdap:domain:example.com"},
		{KeyPrefixIP, "8.8.8.8", "rdap:ip:8.8.8.8"},
		{KeyPrefixASN, "15169", "rdap:asn:15169"},
		{KeyPrefixEntity, "ABC-123", "rdap:entity:ABC-123"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := BuildKey(tt.prefix, tt.value)
			if got != tt.want {
				t.Errorf("BuildKey() = %q, want %q", got, tt.want)
			}
		})
	}
}
