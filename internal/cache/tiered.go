package cache

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"golang.org/x/sync/singleflight"
)

// Layer constants for metrics.
const (
	LayerRAM   = "ram"
	LayerRedis = "redis"
)

// TieredCache implements a two-tier cache (L1: RAM, L2: Redis).
// Reads check L1 first, then L2. Writes go to both.
// L1 is populated on L2 hits (promotion).
type TieredCache struct {
	l1      Cache   // L1 cache (required)
	l2      L2Cache // L2 cache (optional, may be nil)
	group   singleflight.Group
	config  TieredCacheConfig
	metrics MetricsCollector // Optional metrics collector
	logger  *slog.Logger     // Optional logger for debug messages
}

// TieredCacheConfig holds configuration for the tiered cache.
type TieredCacheConfig struct {
	L1Config       MemoryCacheConfig
	L2Config       *RedisCacheConfig // Nil to disable L2
	DefaultTTL     time.Duration
	NegativeTTL    time.Duration
	L1PromotionTTL time.Duration // TTL when promoting from L2 to L1
	EnableL2Writes bool          // Write to L2 on Set (default true)
	// FetchTimeout bounds the upstream fetch inside singleflight independently
	// of the caller's context. This prevents a cancelled caller from aborting
	// a flight that other joined callers are waiting on, and ensures that even
	// a caller with no deadline cannot leave a fetch goroutine running forever.
	// Defaults to 30s. Must be positive.
	FetchTimeout time.Duration
}

// DefaultTieredCacheConfig returns default configuration.
func DefaultTieredCacheConfig() TieredCacheConfig {
	return TieredCacheConfig{
		L1Config:       DefaultMemoryCacheConfig(),
		L2Config:       nil, // L2 disabled by default
		DefaultTTL:     24 * time.Hour,
		NegativeTTL:    1 * time.Hour,
		L1PromotionTTL: 5 * time.Minute,
		EnableL2Writes: true,
		FetchTimeout:   30 * time.Second,
	}
}

// defaultFetchTimeout is used when a config omits FetchTimeout (or sets it
// non-positive). Without it, context.WithTimeout would produce an
// already-expired context and every upstream fetch would fail instantly.
const defaultFetchTimeout = 30 * time.Second

// normalizeConfig enforces invariants on a TieredCacheConfig that are not
// guaranteed when callers build the struct literal directly (bypassing
// DefaultTieredCacheConfig). FetchTimeout must be positive.
func normalizeConfig(cfg TieredCacheConfig) TieredCacheConfig {
	if cfg.FetchTimeout <= 0 {
		cfg.FetchTimeout = defaultFetchTimeout
	}
	return cfg
}

// NewTieredCache creates a new tiered cache using default backend implementations.
func NewTieredCache(cfg TieredCacheConfig) (*TieredCache, error) {
	cfg = normalizeConfig(cfg)

	l1, err := NewMemoryCache(cfg.L1Config)
	if err != nil {
		return nil, err
	}

	var l2 L2Cache
	if cfg.L2Config != nil {
		l2, err = NewRedisCache(*cfg.L2Config)
		if err != nil {
			_ = l1.Close()
			return nil, err
		}
	}

	return &TieredCache{
		l1:     l1,
		l2:     l2,
		config: cfg,
	}, nil
}

// NewTieredCacheWithBackends creates a tiered cache with custom cache backends.
// This is useful for testing or for using custom cache implementations.
// l1 is required, l2 may be nil to disable L2 caching.
func NewTieredCacheWithBackends(l1 Cache, l2 L2Cache, cfg TieredCacheConfig) *TieredCache {
	return &TieredCache{
		l1:     l1,
		l2:     l2,
		config: normalizeConfig(cfg),
	}
}

// SetMetrics sets the metrics collector for the cache.
func (t *TieredCache) SetMetrics(m MetricsCollector) {
	t.metrics = m
}

// SetLogger sets the logger for debug messages.
func (t *TieredCache) SetLogger(l *slog.Logger) {
	t.logger = l
}

// Get retrieves an entry from the cache, checking L1 then L2.
func (t *TieredCache) Get(ctx context.Context, key string) (*Entry, error) {
	// Check L1 first
	start := time.Now()
	entry, err := t.l1.Get(ctx, key)
	if t.metrics != nil {
		t.metrics.RecordOperationDuration(LayerRAM, "get", time.Since(start).Seconds())
	}

	if err == nil {
		if t.metrics != nil {
			t.metrics.RecordHit(LayerRAM)
		}
		return entry, nil
	}

	// L1 miss
	if t.metrics != nil {
		t.metrics.RecordMiss(LayerRAM)
	}

	// If L2 is disabled, return the L1 miss
	if t.l2 == nil {
		return nil, err
	}

	// Check L2
	start = time.Now()
	entry, err = t.l2.Get(ctx, key)
	if t.metrics != nil {
		t.metrics.RecordOperationDuration(LayerRedis, "get", time.Since(start).Seconds())
	}

	if err != nil {
		if t.metrics != nil {
			t.metrics.RecordMiss(LayerRedis)
		}
		return nil, err
	}

	// L2 hit
	if t.metrics != nil {
		t.metrics.RecordHit(LayerRedis)
	}

	// Promote to L1
	t.promoteToL1(ctx, key, entry)

	return entry, nil
}

// promoteToL1 copies an entry from L2 to L1.
func (t *TieredCache) promoteToL1(ctx context.Context, key string, entry *Entry) {
	ttl := t.config.L1PromotionTTL
	if entry.Negative {
		ttl = min(t.config.NegativeTTL, t.config.L1PromotionTTL)
	}

	if err := t.l1.Set(ctx, key, entry.Value, ttl, entry.Negative); err != nil {
		if t.logger != nil {
			t.logger.Debug("failed to promote entry to L1 cache",
				slog.String("key", key),
				slog.String("error", err.Error()),
			)
		}
		if t.metrics != nil {
			t.metrics.RecordPromotionError()
		}
		return
	}

	if t.metrics != nil {
		t.metrics.RecordPromotion()
	}
}

// Set stores an entry in both cache tiers.
func (t *TieredCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration, negative bool) error {
	// Always write to L1
	start := time.Now()
	if err := t.l1.Set(ctx, key, value, ttl, negative); err != nil {
		return err
	}
	if t.metrics != nil {
		t.metrics.RecordOperationDuration(LayerRAM, "set", time.Since(start).Seconds())
	}

	// Write to L2 if enabled (don't return error - L1 write succeeded)
	if t.l2 != nil && t.config.EnableL2Writes {
		start = time.Now()
		if err := t.l2.Set(ctx, key, value, ttl, negative); err != nil {
			if t.logger != nil {
				t.logger.Debug("failed to write to L2 cache",
					slog.String("key", key),
					slog.String("error", err.Error()),
				)
			}
			if t.metrics != nil {
				t.metrics.RecordL2WriteError()
			}
		}
		if t.metrics != nil {
			t.metrics.RecordOperationDuration(LayerRedis, "set", time.Since(start).Seconds())
		}
	}

	return nil
}

// SetWithDefaultTTL stores an entry using the default TTL.
func (t *TieredCache) SetWithDefaultTTL(ctx context.Context, key string, value []byte, negative bool) error {
	ttl := t.config.DefaultTTL
	if negative {
		ttl = t.config.NegativeTTL
	}
	return t.Set(ctx, key, value, ttl, negative)
}

// Delete removes an entry from both cache tiers.
func (t *TieredCache) Delete(ctx context.Context, key string) error {
	// Delete from L1
	if err := t.l1.Delete(ctx, key); err != nil {
		return err
	}

	// Delete from L2 if enabled
	if t.l2 != nil {
		return t.l2.Delete(ctx, key)
	}

	return nil
}

// Clear removes all entries from both cache tiers.
func (t *TieredCache) Clear(ctx context.Context) error {
	if err := t.l1.Clear(ctx); err != nil {
		return err
	}

	if t.l2 != nil {
		return t.l2.Clear(ctx)
	}

	return nil
}

// Stats returns combined cache statistics.
func (t *TieredCache) Stats() TieredStats {
	stats := TieredStats{
		L1: t.l1.Stats(),
	}

	if t.l2 != nil {
		l2Stats := t.l2.Stats()
		stats.L2 = &l2Stats
		stats.L2Available = t.l2.IsAvailable(context.Background())
	}

	return stats
}

// TieredStats holds statistics for both cache tiers.
type TieredStats struct {
	L1          Stats  `json:"l1"`
	L2          *Stats `json:"l2,omitempty"`
	L2Available bool   `json:"l2_available"`
}

// Close releases resources held by both cache tiers.
func (t *TieredCache) Close() error {
	var errs []error

	if err := t.l1.Close(); err != nil {
		errs = append(errs, err)
	}

	if t.l2 != nil {
		if err := t.l2.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// GetOrFetch retrieves from cache or fetches using the provided function.
// Uses singleflight to prevent duplicate fetches for the same key.
//
// The fetch function receives a context that is deliberately detached from the
// caller's ctx (via context.WithoutCancel) and bounded by FetchTimeout. This
// means:
//   - A cancelled caller does not abort a flight that other callers have joined.
//   - The flight is still bounded in time by FetchTimeout (default 30s).
//   - Cache reads on the initial probe still respect the caller's ctx.
func (t *TieredCache) GetOrFetch(ctx context.Context, key string, fetch func(ctx context.Context) ([]byte, error)) ([]byte, bool, error) {
	// Try cache first using caller ctx so the probe is cancellable.
	entry, err := t.Get(ctx, key)
	if err == nil {
		return entry.Value, true, nil
	}

	// Use singleflight to prevent thundering herd.
	// The fetch ctx is detached from the caller ctx so that a cancelled caller
	// does not abort a flight shared with other callers.
	result, err, shared := t.group.Do(key, func() (any, error) {
		// Derive a fetch-scoped context that is independent of any single
		// caller's lifetime. context.WithoutCancel severs cancellation
		// propagation while preserving ctx values (requires Go 1.21+).
		fetchCtx := context.WithoutCancel(ctx)
		fetchCtx, cancel := context.WithTimeout(fetchCtx, t.config.FetchTimeout)
		defer cancel()

		// Double-check cache (another goroutine might have populated it).
		entry, err := t.Get(fetchCtx, key)
		if err == nil {
			return entry.Value, nil
		}

		// Fetch from upstream using the detached, timeout-bounded context.
		value, err := fetch(fetchCtx)
		if err != nil {
			return nil, err
		}

		// Store in cache.
		_ = t.SetWithDefaultTTL(fetchCtx, key, value, false)

		return value, nil
	})

	// Record singleflight metrics
	if t.metrics != nil {
		t.metrics.RecordSingleflight(shared)
	}

	if err != nil {
		return nil, false, err
	}

	return result.([]byte), false, nil
}

// GetOrFetchWithNegative is like GetOrFetch but supports negative caching.
// If fetch returns ErrNotFound, a negative cache entry is stored.
//
// The fetch context is detached from the caller's ctx in the same way as
// GetOrFetch. See GetOrFetch for the full rationale.
func (t *TieredCache) GetOrFetchWithNegative(ctx context.Context, key string, fetch func(ctx context.Context) ([]byte, error), notFoundErr error) ([]byte, bool, error) {
	// Try cache first using caller ctx so the probe is cancellable.
	entry, err := t.Get(ctx, key)
	if err == nil {
		if entry.Negative {
			return nil, true, notFoundErr
		}
		return entry.Value, true, nil
	}

	// Use singleflight to prevent thundering herd.
	result, err, shared := t.group.Do(key, func() (any, error) {
		// Derive a fetch-scoped context detached from the caller ctx.
		fetchCtx := context.WithoutCancel(ctx)
		fetchCtx, cancel := context.WithTimeout(fetchCtx, t.config.FetchTimeout)
		defer cancel()

		// Double-check cache.
		entry, err := t.Get(fetchCtx, key)
		if err == nil {
			if entry.Negative {
				return nil, notFoundErr
			}
			return entry.Value, nil
		}

		// Fetch from upstream using the detached context.
		value, fetchErr := fetch(fetchCtx)
		if fetchErr != nil {
			// Check if this is a "not found" error that should be negatively cached.
			if errors.Is(fetchErr, notFoundErr) {
				_ = t.SetWithDefaultTTL(fetchCtx, key, nil, true)
				return nil, notFoundErr
			}
			return nil, fetchErr
		}

		// Store in cache.
		_ = t.SetWithDefaultTTL(fetchCtx, key, value, false)

		return value, nil
	})

	// Record singleflight metrics
	if t.metrics != nil {
		t.metrics.RecordSingleflight(shared)
	}

	if err != nil {
		return nil, false, err
	}

	if result == nil {
		return nil, false, nil
	}

	return result.([]byte), false, nil
}

// L1 returns the L1 cache for direct access.
func (t *TieredCache) L1() Cache {
	return t.l1
}

// L2 returns the L2 cache for direct access, or nil if disabled.
func (t *TieredCache) L2() L2Cache {
	return t.l2
}

// HasL2 returns true if L2 cache is configured.
func (t *TieredCache) HasL2() bool {
	return t.l2 != nil
}
