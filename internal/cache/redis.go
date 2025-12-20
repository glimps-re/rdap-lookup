package cache

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// Compile-time interface checks.
var (
	_ Cache   = (*RedisCache)(nil)
	_ L2Cache = (*RedisCache)(nil)
)

// RedisCache implements a Redis-backed cache.
type RedisCache struct {
	client *redis.Client
	prefix string
	hits   atomic.Uint64
	misses atomic.Uint64
}

// RedisCacheConfig holds configuration for Redis cache.
type RedisCacheConfig struct {
	Addr         string        // Redis address (host:port)
	Password     string        // Redis password
	DB           int           // Redis database number
	KeyPrefix    string        // Prefix for all keys
	DialTimeout  time.Duration // Connection timeout
	ReadTimeout  time.Duration // Read timeout
	WriteTimeout time.Duration // Write timeout
	PoolSize     int           // Connection pool size
}

// DefaultRedisCacheConfig returns default configuration.
func DefaultRedisCacheConfig() RedisCacheConfig {
	return RedisCacheConfig{
		Addr:         "localhost:6379",
		Password:     "",
		DB:           0,
		KeyPrefix:    "",
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
		PoolSize:     10,
	}
}

// NewRedisCache creates a new Redis cache client.
func NewRedisCache(cfg RedisCacheConfig) (*RedisCache, error) {
	client := redis.NewClient(&redis.Options{
		Addr:         cfg.Addr,
		Password:     cfg.Password,
		DB:           cfg.DB,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		PoolSize:     cfg.PoolSize,
	})

	return &RedisCache{
		client: client,
		prefix: cfg.KeyPrefix,
	}, nil
}

// redisEntry is the format stored in Redis.
type redisEntry struct {
	Value    []byte `json:"v"`
	Negative bool   `json:"n,omitempty"`
}

// prefixedKey returns the key with optional prefix.
func (r *RedisCache) prefixedKey(key string) string {
	if r.prefix == "" {
		return key
	}
	return r.prefix + key
}

// Get retrieves an entry from Redis.
func (r *RedisCache) Get(ctx context.Context, key string) (*Entry, error) {
	data, err := r.client.Get(ctx, r.prefixedKey(key)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			r.misses.Add(1)
			return nil, ErrCacheMiss
		}
		return nil, err
	}

	var re redisEntry
	if err := json.Unmarshal(data, &re); err != nil {
		// If unmarshal fails, the data is corrupted - treat as miss
		r.misses.Add(1)
		return nil, ErrCacheMiss
	}

	r.hits.Add(1)
	return &Entry{
		Key:      key,
		Value:    re.Value,
		Negative: re.Negative,
	}, nil
}

// Set stores an entry in Redis with TTL.
func (r *RedisCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration, negative bool) error {
	re := redisEntry{
		Value:    value,
		Negative: negative,
	}

	data, err := json.Marshal(re)
	if err != nil {
		return err
	}

	return r.client.Set(ctx, r.prefixedKey(key), data, ttl).Err()
}

// Delete removes an entry from Redis.
func (r *RedisCache) Delete(ctx context.Context, key string) error {
	return r.client.Del(ctx, r.prefixedKey(key)).Err()
}

// Clear removes all entries with the configured prefix.
// Warning: This uses SCAN which can be slow on large datasets.
func (r *RedisCache) Clear(ctx context.Context) error {
	if r.prefix == "" {
		return r.client.FlushDB(ctx).Err()
	}

	// Use SCAN to find and delete keys with prefix
	var cursor uint64
	for {
		keys, nextCursor, err := r.client.Scan(ctx, cursor, r.prefix+"*", 100).Result()
		if err != nil {
			return err
		}

		if len(keys) > 0 {
			if err := r.client.Del(ctx, keys...).Err(); err != nil {
				return err
			}
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return nil
}

// Stats returns cache statistics.
func (r *RedisCache) Stats() Stats {
	hits := r.hits.Load()
	misses := r.misses.Load()
	total := hits + misses

	var hitRate float64
	if total > 0 {
		hitRate = float64(hits) / float64(total)
	}

	return Stats{
		Hits:    hits,
		Misses:  misses,
		HitRate: hitRate,
		// Note: Entries and SizeBytes would require additional Redis commands
	}
}

// Close closes the Redis connection.
func (r *RedisCache) Close() error {
	return r.client.Close()
}

// Ping checks the Redis connection.
func (r *RedisCache) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

// IsAvailable returns true if Redis is reachable.
func (r *RedisCache) IsAvailable(ctx context.Context) bool {
	return r.Ping(ctx) == nil
}
