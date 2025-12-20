package cache

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

// Compile-time interface check.
var _ Cache = (*MemoryCache)(nil)

// MemoryCache implements an in-memory LRU cache with TTL support.
type MemoryCache struct {
	cache     *lru.Cache[string, *Entry]
	maxSize   int64 // Maximum size in bytes
	sizeBytes atomic.Int64
	hits      atomic.Uint64
	misses    atomic.Uint64
	evictions atomic.Uint64
	mu        sync.RWMutex
}

// MemoryCacheConfig holds configuration for the memory cache.
type MemoryCacheConfig struct {
	MaxEntries int   // Maximum number of entries
	MaxSize    int64 // Maximum size in bytes (0 = unlimited)
}

// DefaultMemoryCacheConfig returns default configuration.
func DefaultMemoryCacheConfig() MemoryCacheConfig {
	return MemoryCacheConfig{
		MaxEntries: 10000,
		MaxSize:    100 * 1024 * 1024, // 100MB
	}
}

// NewMemoryCache creates a new in-memory LRU cache.
func NewMemoryCache(cfg MemoryCacheConfig) (*MemoryCache, error) {
	mc := &MemoryCache{
		maxSize: cfg.MaxSize,
	}

	// Create LRU cache with eviction callback
	cache, err := lru.NewWithEvict[string, *Entry](cfg.MaxEntries, mc.onEvict)
	if err != nil {
		return nil, err
	}
	mc.cache = cache

	return mc, nil
}

// onEvict is called when an entry is evicted from the cache.
func (m *MemoryCache) onEvict(key string, entry *Entry) {
	if entry != nil {
		m.sizeBytes.Add(-int64(len(entry.Value)))
		m.evictions.Add(1)
	}
}

// Get retrieves an entry from the cache.
func (m *MemoryCache) Get(_ context.Context, key string) (*Entry, error) {
	m.mu.RLock()
	entry, ok := m.cache.Get(key)
	m.mu.RUnlock()

	if !ok {
		m.misses.Add(1)
		return nil, ErrCacheMiss
	}

	// Check if expired
	if entry.IsExpired() {
		m.mu.Lock()
		m.cache.Remove(key)
		m.sizeBytes.Add(-int64(len(entry.Value)))
		m.mu.Unlock()
		m.misses.Add(1)
		return nil, ErrCacheMiss
	}

	m.hits.Add(1)
	return entry, nil
}

// Set stores an entry in the cache.
func (m *MemoryCache) Set(_ context.Context, key string, value []byte, ttl time.Duration, negative bool) error {
	entry := &Entry{
		Key:       key,
		Value:     value,
		ExpiresAt: time.Now().Add(ttl),
		Negative:  negative,
	}

	entrySize := int64(len(value))

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if we need to evict to make room (if size limit is set)
	if m.maxSize > 0 {
		// Remove old entry size if replacing
		if old, ok := m.cache.Peek(key); ok {
			m.sizeBytes.Add(-int64(len(old.Value)))
		}

		// Evict entries until we have room
		for m.sizeBytes.Load()+entrySize > m.maxSize && m.cache.Len() > 0 {
			m.cache.RemoveOldest()
		}
	}

	m.cache.Add(key, entry)
	m.sizeBytes.Add(entrySize)

	return nil
}

// Delete removes an entry from the cache.
func (m *MemoryCache) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if entry, ok := m.cache.Peek(key); ok {
		m.sizeBytes.Add(-int64(len(entry.Value)))
		m.cache.Remove(key)
	}

	return nil
}

// Clear removes all entries from the cache.
func (m *MemoryCache) Clear(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.cache.Purge()
	m.sizeBytes.Store(0)

	return nil
}

// Stats returns cache statistics.
func (m *MemoryCache) Stats() Stats {
	hits := m.hits.Load()
	misses := m.misses.Load()
	total := hits + misses

	var hitRate float64
	if total > 0 {
		hitRate = float64(hits) / float64(total)
	}

	m.mu.RLock()
	entries := m.cache.Len()
	m.mu.RUnlock()

	return Stats{
		Hits:      hits,
		Misses:    misses,
		Entries:   entries,
		SizeBytes: m.sizeBytes.Load(),
		Evictions: m.evictions.Load(),
		HitRate:   hitRate,
	}
}

// Close releases resources held by the cache.
func (m *MemoryCache) Close() error {
	return m.Clear(context.Background())
}

// Len returns the number of entries in the cache.
func (m *MemoryCache) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cache.Len()
}
