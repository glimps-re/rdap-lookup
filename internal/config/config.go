// Package config provides configuration management for rdap-lookup.
// Configuration is loaded from environment variables with sensible defaults.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds all configuration for the rdap-lookup service.
type Config struct {
	Server    ServerConfig
	Cache     CacheConfig
	RDAP      RDAPConfig
	Bootstrap BootstrapConfig
	Log       LogConfig
	RateLimit RateLimitConfig
	Batch     BatchConfig
	WHOIS     WHOISConfig
}

// WHOISConfig holds WHOIS fallback configuration.
type WHOISConfig struct {
	// Enabled controls whether WHOIS fallback is enabled (default: false).
	// When enabled, the service will query WHOIS servers for TLDs without RDAP support.
	Enabled bool
	// Timeout is the timeout for WHOIS queries (default: 10s).
	Timeout time.Duration
	// MaxResponseSize is the maximum WHOIS response size in bytes (default: 64KB).
	// This prevents memory exhaustion from malicious or malformed responses.
	MaxResponseSize int64
}

// ServerConfig holds HTTP server configuration.
type ServerConfig struct {
	// ListenAddr is the address to listen on (default: ":8080").
	ListenAddr string
	// ReadTimeout is the maximum duration for reading the entire request (default: 30s).
	ReadTimeout time.Duration
	// WriteTimeout is the maximum duration before timing out writes of the response (default: 30s).
	WriteTimeout time.Duration
	// ShutdownTimeout is the maximum duration to wait for graceful shutdown (default: 30s).
	ShutdownTimeout time.Duration
	// TrustProxy enables trusting X-Forwarded-For headers for client IP extraction.
	//
	// SECURITY WARNING: Only enable this when running behind a trusted reverse proxy
	// (e.g., nginx, Cloudflare, AWS ALB, Traefik). If the server is directly exposed
	// to the internet with TrustProxy=true, attackers can spoof their IP address by
	// setting X-Forwarded-For headers, bypassing rate limiting and IP-based security.
	//
	// Default: false (uses direct connection IP)
	// Set via RDAP_TRUST_PROXY environment variable.
	TrustProxy bool
	// BodyLimit is the maximum allowed request body size (default: 1MB).
	BodyLimit string
}

// CacheConfig holds cache configuration.
type CacheConfig struct {
	// TTL is the default cache TTL for positive responses (default: 24h).
	TTL time.Duration
	// NegativeTTL is the cache TTL for "not found" responses (default: 1h).
	NegativeTTL time.Duration
	// RAM holds RAM cache (L1) configuration.
	RAM RAMCacheConfig
	// Redis holds Redis cache (L2) configuration.
	Redis RedisCacheConfig
}

// RAMCacheConfig holds RAM cache configuration.
type RAMCacheConfig struct {
	// Enabled controls whether RAM cache is enabled (default: true).
	Enabled bool
	// MaxSize is the maximum RAM cache size in bytes (default: 100MB).
	MaxSize int64
}

// RedisCacheConfig holds Redis cache configuration.
type RedisCacheConfig struct {
	// Enabled controls whether Redis cache is enabled (default: false).
	Enabled bool
	// Addr is the Redis server address (host:port).
	Addr string
	// Password is the Redis password (optional).
	Password string
	// DB is the Redis database number (default: 0).
	DB int
}

// RDAPConfig holds RDAP client configuration.
type RDAPConfig struct {
	// Timeout is the timeout for upstream RDAP requests (default: 10s).
	Timeout time.Duration
	// MaxRetries is the maximum number of retries for failed requests (default: 2).
	MaxRetries int
}

// BootstrapConfig holds IANA bootstrap configuration.
type BootstrapConfig struct {
	// RefreshInterval is how often to refresh IANA bootstrap data (default: 24h).
	RefreshInterval time.Duration
}

// LogConfig holds logging configuration.
type LogConfig struct {
	// Level is the log level: debug, info, warn, error (default: info).
	Level string
	// Format is the log format: json, text (default: json).
	Format string
}

// RateLimitConfig holds rate limiting configuration.
type RateLimitConfig struct {
	// Enabled controls whether rate limiting is enabled (default: true).
	Enabled bool
	// RPS is the requests per second limit per IP (default: 1000).
	// Set via RDAP_RATE_LIMIT_RPS environment variable.
	RPS float64
	// Burst is the maximum burst size per IP (default: 2000).
	// Set via RDAP_RATE_LIMIT_BURST environment variable.
	Burst int
}

// BatchConfig holds batch processing configuration.
type BatchConfig struct {
	// Concurrency is the maximum number of concurrent queries per batch (default: 10).
	Concurrency int
	// Timeout is the timeout for the entire batch operation (default: 30s).
	Timeout time.Duration
}

// Load loads configuration from environment variables.
func Load() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			ListenAddr:      getEnv("RDAP_LISTEN_ADDR", ":8080"),
			ReadTimeout:     getDurationEnv("RDAP_READ_TIMEOUT", 30*time.Second),
			WriteTimeout:    getDurationEnv("RDAP_WRITE_TIMEOUT", 30*time.Second),
			ShutdownTimeout: getDurationEnv("RDAP_SHUTDOWN_TIMEOUT", 30*time.Second),
			TrustProxy:      getBoolEnv("RDAP_TRUST_PROXY", false),
			BodyLimit:       getEnv("RDAP_BODY_LIMIT", "1MB"),
		},
		Cache: CacheConfig{
			TTL:         getDurationEnv("RDAP_CACHE_TTL", 24*time.Hour),
			NegativeTTL: getDurationEnv("RDAP_CACHE_NEGATIVE_TTL", 1*time.Hour),
			RAM: RAMCacheConfig{
				Enabled: getBoolEnv("RDAP_CACHE_RAM_ENABLED", true),
				MaxSize: getSizeEnv("RDAP_CACHE_RAM_MAX_SIZE", 100*1024*1024), // 100MB
			},
			Redis: RedisCacheConfig{
				Enabled:  getBoolEnv("RDAP_CACHE_REDIS_ENABLED", false),
				Addr:     getEnv("RDAP_CACHE_REDIS_ADDR", ""),
				Password: getEnv("RDAP_CACHE_REDIS_PASSWORD", ""),
				DB:       getIntEnv("RDAP_CACHE_REDIS_DB", 0),
			},
		},
		RDAP: RDAPConfig{
			Timeout:    getDurationEnv("RDAP_CLIENT_TIMEOUT", 10*time.Second),
			MaxRetries: getIntEnv("RDAP_CLIENT_MAX_RETRIES", 2),
		},
		Bootstrap: BootstrapConfig{
			RefreshInterval: getDurationEnv("RDAP_BOOTSTRAP_REFRESH", 24*time.Hour),
		},
		Log: LogConfig{
			Level:  getEnv("RDAP_LOG_LEVEL", "info"),
			Format: getEnv("RDAP_LOG_FORMAT", "json"),
		},
		RateLimit: RateLimitConfig{
			Enabled: getBoolEnv("RDAP_RATE_LIMIT_ENABLED", true),
			RPS:     getFloatEnv("RDAP_RATE_LIMIT_RPS", 1000),
			Burst:   getIntEnv("RDAP_RATE_LIMIT_BURST", 2000),
		},
		Batch: BatchConfig{
			Concurrency: getIntEnv("RDAP_BATCH_CONCURRENCY", 10),
			Timeout:     getDurationEnv("RDAP_BATCH_TIMEOUT", 30*time.Second),
		},
		WHOIS: WHOISConfig{
			Enabled:         getBoolEnv("RDAP_WHOIS_ENABLED", false),
			Timeout:         getDurationEnv("RDAP_WHOIS_TIMEOUT", 10*time.Second),
			MaxResponseSize: getSizeEnv("RDAP_WHOIS_MAX_RESPONSE_SIZE", 64*1024), // 64KB
		},
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if c.Server.ListenAddr == "" {
		return fmt.Errorf("listen address cannot be empty")
	}

	if c.Server.ReadTimeout <= 0 {
		return fmt.Errorf("read timeout must be positive")
	}

	if c.Server.WriteTimeout <= 0 {
		return fmt.Errorf("write timeout must be positive")
	}

	if c.Server.ShutdownTimeout <= 0 {
		return fmt.Errorf("shutdown timeout must be positive")
	}

	if c.Cache.TTL <= 0 {
		return fmt.Errorf("cache TTL must be positive")
	}

	if c.Cache.NegativeTTL <= 0 {
		return fmt.Errorf("negative cache TTL must be positive")
	}

	if c.Cache.RAM.Enabled && c.Cache.RAM.MaxSize <= 0 {
		return fmt.Errorf("RAM cache max size must be positive")
	}

	if c.Cache.Redis.Enabled && c.Cache.Redis.Addr == "" {
		return fmt.Errorf("redis address required when redis cache is enabled")
	}

	if c.RDAP.Timeout <= 0 {
		return fmt.Errorf("RDAP timeout must be positive")
	}

	if c.RDAP.MaxRetries < 0 {
		return fmt.Errorf("RDAP max retries cannot be negative")
	}

	if c.Bootstrap.RefreshInterval <= 0 {
		return fmt.Errorf("bootstrap refresh interval must be positive")
	}

	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[c.Log.Level] {
		return fmt.Errorf("invalid log level: %s (valid: debug, info, warn, error)", c.Log.Level)
	}

	validFormats := map[string]bool{"json": true, "text": true}
	if !validFormats[c.Log.Format] {
		return fmt.Errorf("invalid log format: %s (valid: json, text)", c.Log.Format)
	}

	if c.Batch.Concurrency <= 0 {
		return fmt.Errorf("batch concurrency must be positive")
	}

	if c.Batch.Timeout <= 0 {
		return fmt.Errorf("batch timeout must be positive")
	}

	// WHOIS validation (only when enabled)
	if c.WHOIS.Enabled {
		if c.WHOIS.Timeout <= 0 {
			return fmt.Errorf("WHOIS timeout must be positive")
		}
		if c.WHOIS.MaxResponseSize <= 0 {
			return fmt.Errorf("WHOIS max response size must be positive")
		}
	}

	return nil
}

// getEnv returns environment variable value or default.
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getBoolEnv returns environment variable as bool or default.
func getBoolEnv(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	b, err := strconv.ParseBool(value)
	if err != nil {
		return defaultValue
	}
	return b
}

// getIntEnv returns environment variable as int or default.
func getIntEnv(key string, defaultValue int) int {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	i, err := strconv.Atoi(value)
	if err != nil {
		return defaultValue
	}
	return i
}

// getFloatEnv returns environment variable as float64 or default.
func getFloatEnv(key string, defaultValue float64) float64 {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	f, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return defaultValue
	}
	return f
}

// getDurationEnv returns environment variable as duration or default.
func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return defaultValue
	}
	return d
}

// getSizeEnv returns environment variable as size in bytes or default.
// Supports suffixes: B, KB, MB, GB (case insensitive).
func getSizeEnv(key string, defaultValue int64) int64 {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}

	// Try parsing as plain number first
	if size, err := strconv.ParseInt(value, 10, 64); err == nil {
		return size
	}

	// Parse with suffix
	var multiplier int64 = 1
	var numStr string

	upperValue := value
	switch {
	case len(value) >= 2 && (value[len(value)-2:] == "GB" || value[len(value)-2:] == "gb"):
		multiplier = 1024 * 1024 * 1024
		numStr = value[:len(value)-2]
	case len(value) >= 2 && (value[len(value)-2:] == "MB" || value[len(value)-2:] == "mb"):
		multiplier = 1024 * 1024
		numStr = value[:len(value)-2]
	case len(value) >= 2 && (value[len(value)-2:] == "KB" || value[len(value)-2:] == "kb"):
		multiplier = 1024
		numStr = value[:len(value)-2]
	case len(value) >= 1 && (upperValue[len(value)-1:] == "B" || upperValue[len(value)-1:] == "b"):
		numStr = value[:len(value)-1]
	default:
		return defaultValue
	}

	size, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		return defaultValue
	}

	return size * multiplier
}
