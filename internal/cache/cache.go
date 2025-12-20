// Package cache provides caching functionality for RDAP responses.
package cache

import (
	"context"
	"errors"
	"time"
)

// ErrCacheMiss is returned when a key is not found in the cache.
var ErrCacheMiss = errors.New("cache miss")

// Entry represents a cached item with metadata.
type Entry struct {
	Key       string    `json:"key"`
	Value     []byte    `json:"value"`
	ExpiresAt time.Time `json:"expires_at"`
	Negative  bool      `json:"negative"` // True if this is a negative cache entry (not found)
}

// IsExpired returns true if the entry has expired.
func (e *Entry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// TTL returns the remaining time to live.
func (e *Entry) TTL() time.Duration {
	ttl := time.Until(e.ExpiresAt)
	if ttl < 0 {
		return 0
	}
	return ttl
}

// Cache defines the interface for cache implementations.
type Cache interface {
	// Get retrieves an entry from the cache.
	// Returns ErrCacheMiss if the key is not found or expired.
	Get(ctx context.Context, key string) (*Entry, error)

	// Set stores an entry in the cache with the given TTL.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration, negative bool) error

	// Delete removes an entry from the cache.
	Delete(ctx context.Context, key string) error

	// Clear removes all entries from the cache.
	Clear(ctx context.Context) error

	// Stats returns cache statistics.
	Stats() Stats

	// Close releases any resources held by the cache.
	Close() error
}

// L2Cache extends Cache with availability checking for remote caches.
// This interface is typically implemented by Redis or other network-based caches.
type L2Cache interface {
	Cache
	// IsAvailable returns true if the cache backend is reachable.
	IsAvailable(ctx context.Context) bool
	// Ping checks the connection to the cache backend.
	Ping(ctx context.Context) error
}

// Stats holds cache statistics.
type Stats struct {
	Hits      uint64  `json:"hits"`
	Misses    uint64  `json:"misses"`
	Entries   int     `json:"entries"`
	SizeBytes int64   `json:"size_bytes"`
	Evictions uint64  `json:"evictions"`
	HitRate   float64 `json:"hit_rate"`
}

// KeyPrefix constants for different RDAP types.
const (
	KeyPrefixDomain     = "rdap:domain:"
	KeyPrefixIP         = "rdap:ip:"
	KeyPrefixASN        = "rdap:asn:"
	KeyPrefixEntity     = "rdap:entity:"
	KeyPrefixNameserver = "rdap:ns:"
)

// BuildKey creates a cache key from type prefix and value.
func BuildKey(prefix, value string) string {
	return prefix + value
}

// MetricsCollector defines the interface for recording cache metrics.
// This allows the cache package to record metrics without a direct dependency
// on the metrics package.
type MetricsCollector interface {
	// RecordHit records a cache hit for the given layer.
	RecordHit(layer string)
	// RecordMiss records a cache miss for the given layer.
	RecordMiss(layer string)
	// RecordEviction records a cache eviction for the given layer.
	RecordEviction(layer string)
	// SetSize sets the current cache size in bytes for the given layer.
	SetSize(layer string, sizeBytes int64)
	// SetEntries sets the current number of entries for the given layer.
	SetEntries(layer string, count int)
	// RecordOperationDuration records the duration of a cache operation.
	RecordOperationDuration(layer, operation string, seconds float64)
	// RecordPromotion records a cache promotion from L2 to L1.
	RecordPromotion()
	// RecordPromotionError records a failed L2->L1 promotion.
	RecordPromotionError()
	// RecordSingleflight records a singleflight operation result.
	RecordSingleflight(shared bool)
	// RecordL2WriteError records an L2 cache write failure.
	RecordL2WriteError()
}
