package cache

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func BenchmarkMemoryCache_Set(b *testing.B) {
	cfg := MemoryCacheConfig{
		MaxEntries: 100000,
		MaxSize:    100 * 1024 * 1024, // 100MB
	}
	c, err := NewMemoryCache(cfg)
	if err != nil {
		b.Fatalf("NewMemoryCache() error = %v", err)
	}
	defer func() { _ = c.Close() }()

	ctx := context.Background()
	value := []byte(`{"name": "example.com", "status": ["active"]}`)

	b.ResetTimer()
	b.ReportAllocs()

	for i := range b.N {
		key := fmt.Sprintf("rdap:domain:example%d.com", i)
		if err := c.Set(ctx, key, value, time.Hour, false); err != nil {
			b.Fatalf("Set() error = %v", err)
		}
	}
}

func BenchmarkMemoryCache_Get(b *testing.B) {
	cfg := MemoryCacheConfig{
		MaxEntries: 100000,
		MaxSize:    100 * 1024 * 1024, // 100MB
	}
	c, err := NewMemoryCache(cfg)
	if err != nil {
		b.Fatalf("NewMemoryCache() error = %v", err)
	}
	defer func() { _ = c.Close() }()

	ctx := context.Background()
	value := []byte(`{"name": "example.com", "status": ["active"]}`)

	// Pre-populate cache
	for i := range 10000 {
		key := fmt.Sprintf("rdap:domain:example%d.com", i)
		if err := c.Set(ctx, key, value, time.Hour, false); err != nil {
			b.Fatalf("Set() error = %v", err)
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := range b.N {
		key := fmt.Sprintf("rdap:domain:example%d.com", i%10000)
		if _, err := c.Get(ctx, key); err != nil && !errors.Is(err, ErrCacheMiss) {
			b.Fatalf("Get() error = %v", err)
		}
	}
}

func BenchmarkMemoryCache_GetMiss(b *testing.B) {
	cfg := MemoryCacheConfig{
		MaxEntries: 1000,
		MaxSize:    10 * 1024 * 1024, // 10MB
	}
	c, err := NewMemoryCache(cfg)
	if err != nil {
		b.Fatalf("NewMemoryCache() error = %v", err)
	}
	defer func() { _ = c.Close() }()

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := range b.N {
		key := fmt.Sprintf("rdap:domain:nonexistent%d.com", i)
		if _, err := c.Get(ctx, key); !errors.Is(err, ErrCacheMiss) {
			b.Fatalf("Get() error = %v, want ErrCacheMiss", err)
		}
	}
}

func BenchmarkTieredCache_L1Hit(b *testing.B) {
	cfg := DefaultTieredCacheConfig()
	cfg.L1Config.MaxEntries = 100000
	cfg.L1Config.MaxSize = 100 * 1024 * 1024

	c, err := NewTieredCache(cfg)
	if err != nil {
		b.Fatalf("NewTieredCache() error = %v", err)
	}
	defer func() { _ = c.Close() }()

	ctx := context.Background()
	value := []byte(`{"name": "example.com", "status": ["active"]}`)

	// Pre-populate L1 cache
	for i := range 10000 {
		key := fmt.Sprintf("rdap:domain:example%d.com", i)
		if err := c.Set(ctx, key, value, time.Hour, false); err != nil {
			b.Fatalf("Set() error = %v", err)
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := range b.N {
		key := fmt.Sprintf("rdap:domain:example%d.com", i%10000)
		if _, err := c.Get(ctx, key); err != nil {
			b.Fatalf("Get() error = %v", err)
		}
	}
}

func BenchmarkTieredCache_GetOrFetch_CacheHit(b *testing.B) {
	cfg := DefaultTieredCacheConfig()
	cfg.L1Config.MaxEntries = 100000
	cfg.L1Config.MaxSize = 100 * 1024 * 1024

	c, err := NewTieredCache(cfg)
	if err != nil {
		b.Fatalf("NewTieredCache() error = %v", err)
	}
	defer func() { _ = c.Close() }()

	ctx := context.Background()
	value := []byte(`{"name": "example.com", "status": ["active"]}`)

	// Pre-populate cache
	for i := range 10000 {
		key := fmt.Sprintf("rdap:domain:example%d.com", i)
		if err := c.Set(ctx, key, value, time.Hour, false); err != nil {
			b.Fatalf("Set() error = %v", err)
		}
	}

	fetch := func() ([]byte, error) {
		return value, nil
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := range b.N {
		key := fmt.Sprintf("rdap:domain:example%d.com", i%10000)
		if _, _, err := c.GetOrFetch(ctx, key, fetch); err != nil {
			b.Fatalf("GetOrFetch() error = %v", err)
		}
	}
}

func BenchmarkTieredCache_GetOrFetch_CacheMiss(b *testing.B) {
	cfg := DefaultTieredCacheConfig()
	cfg.L1Config.MaxEntries = 100000
	cfg.L1Config.MaxSize = 100 * 1024 * 1024

	c, err := NewTieredCache(cfg)
	if err != nil {
		b.Fatalf("NewTieredCache() error = %v", err)
	}
	defer func() { _ = c.Close() }()

	ctx := context.Background()
	value := []byte(`{"name": "example.com", "status": ["active"]}`)

	fetch := func() ([]byte, error) {
		return value, nil
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := range b.N {
		// Use unique keys to always miss
		key := fmt.Sprintf("rdap:domain:new%d.com", i)
		if _, _, err := c.GetOrFetch(ctx, key, fetch); err != nil {
			b.Fatalf("GetOrFetch() error = %v", err)
		}
	}
}

func BenchmarkBuildKey(b *testing.B) {
	b.ReportAllocs()

	for b.Loop() {
		_ = BuildKey(KeyPrefixDomain, "example.com")
	}
}

func BenchmarkMemoryCache_Parallel_Get(b *testing.B) {
	cfg := MemoryCacheConfig{
		MaxEntries: 100000,
		MaxSize:    100 * 1024 * 1024, // 100MB
	}
	c, err := NewMemoryCache(cfg)
	if err != nil {
		b.Fatalf("NewMemoryCache() error = %v", err)
	}
	defer func() { _ = c.Close() }()

	ctx := context.Background()
	value := []byte(`{"name": "example.com", "status": ["active"]}`)

	// Pre-populate cache
	for i := range 10000 {
		key := fmt.Sprintf("rdap:domain:example%d.com", i)
		if err := c.Set(ctx, key, value, time.Hour, false); err != nil {
			b.Fatalf("Set() error = %v", err)
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("rdap:domain:example%d.com", i%10000)
			if _, err := c.Get(ctx, key); err != nil && !errors.Is(err, ErrCacheMiss) {
				b.Fatalf("Get() error = %v", err)
			}
			i++
		}
	})
}

func BenchmarkTieredCache_Parallel_GetOrFetch(b *testing.B) {
	cfg := DefaultTieredCacheConfig()
	cfg.L1Config.MaxEntries = 100000
	cfg.L1Config.MaxSize = 100 * 1024 * 1024

	c, err := NewTieredCache(cfg)
	if err != nil {
		b.Fatalf("NewTieredCache() error = %v", err)
	}
	defer func() { _ = c.Close() }()

	ctx := context.Background()
	value := []byte(`{"name": "example.com", "status": ["active"]}`)

	// Pre-populate cache
	for i := range 10000 {
		key := fmt.Sprintf("rdap:domain:example%d.com", i)
		if err := c.Set(ctx, key, value, time.Hour, false); err != nil {
			b.Fatalf("Set() error = %v", err)
		}
	}

	fetch := func() ([]byte, error) {
		return value, nil
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := fmt.Sprintf("rdap:domain:example%d.com", i%10000)
			if _, _, err := c.GetOrFetch(ctx, key, fetch); err != nil {
				b.Fatalf("GetOrFetch() error = %v", err)
			}
			i++
		}
	})
}
