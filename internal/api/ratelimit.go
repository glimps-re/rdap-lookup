// Package api provides HTTP handlers and middleware for the RDAP lookup service.
package api

import (
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/glimps-re/rdap-lookup/internal/metrics"
	"github.com/labstack/echo/v4"
	"golang.org/x/time/rate"
)

// Rate limiter capacity limits.
const (
	// maxRateLimiterEntries limits the rate limiter map size to prevent memory exhaustion.
	maxRateLimiterEntries = 100000
	// warningThreshold80 is 80% of capacity for first warning.
	warningThreshold80 = 80000
	// warningThreshold90 is 90% of capacity for second warning.
	warningThreshold90 = 90000
	// maxSubnetLimiterEntries limits the subnet fallback map size.
	maxSubnetLimiterEntries = 10000
)

// IPRateLimiter provides per-IP rate limiting using token bucket algorithm.
// When the per-IP map reaches capacity, it falls back to subnet-based limiting.
type IPRateLimiter struct {
	limiters       sync.Map // map[string]*rateLimiterEntry
	subnetLimiters sync.Map // map[string]*rateLimiterEntry (fallback)
	rate           rate.Limit
	burst          int
	cleanup        *time.Ticker
	done           chan struct{}
	size           atomic.Int64 // Track number of IP entries
	subnetSize     atomic.Int64 // Track number of subnet entries
	logger         *slog.Logger
	metrics        *metrics.Metrics
	capacityWarned atomic.Bool // Prevent log spam at 80%
	criticalWarned atomic.Bool // Prevent log spam at 90%
}

// rateLimiterEntry holds a rate limiter and its last access time.
type rateLimiterEntry struct {
	limiter    *rate.Limiter
	lastAccess time.Time
	mu         sync.Mutex
}

// NewIPRateLimiter creates a rate limiter with specified rate and burst.
// The rate is specified in requests per second, burst is the maximum burst size.
func NewIPRateLimiter(rps float64, burst int, logger *slog.Logger, m *metrics.Metrics) *IPRateLimiter {
	rl := &IPRateLimiter{
		rate:    rate.Limit(rps),
		burst:   burst,
		done:    make(chan struct{}),
		logger:  logger,
		metrics: m,
	}

	// Start cleanup goroutine to remove stale entries
	rl.cleanup = time.NewTicker(5 * time.Minute)
	go rl.cleanupLoop()

	return rl
}

// getLimiter returns the rate limiter for the given IP, creating one if needed.
// Returns nil only if both IP and subnet maps are at capacity (true fail-closed).
func (rl *IPRateLimiter) getLimiter(ip string) *rate.Limiter {
	now := time.Now()
	currentSize := rl.size.Load()

	// Update metrics
	if rl.metrics != nil {
		rl.metrics.RateLimiterEntries.Set(float64(currentSize))
		rl.metrics.RateLimiterSubnetEntries.Set(float64(rl.subnetSize.Load()))
	}

	// Try to get existing limiter
	if val, ok := rl.limiters.Load(ip); ok {
		entry := val.(*rateLimiterEntry)
		entry.mu.Lock()
		entry.lastAccess = now
		entry.mu.Unlock()
		return entry.limiter
	}

	// Log warnings at capacity thresholds
	rl.logCapacityWarnings(currentSize)

	// Check size limit - use subnet fallback at capacity
	if currentSize >= maxRateLimiterEntries {
		if rl.metrics != nil {
			rl.metrics.RateLimiterAtCapacity.Inc()
		}
		return rl.getSubnetLimiter(ip)
	}

	// Create new limiter
	entry := &rateLimiterEntry{
		limiter:    rate.NewLimiter(rl.rate, rl.burst),
		lastAccess: now,
	}

	// Store it (another goroutine might have created one in the meantime)
	actual, loaded := rl.limiters.LoadOrStore(ip, entry)
	if !loaded {
		rl.size.Add(1)
	}
	return actual.(*rateLimiterEntry).limiter
}

// logCapacityWarnings logs warnings when approaching capacity thresholds.
func (rl *IPRateLimiter) logCapacityWarnings(currentSize int64) {
	if rl.logger == nil {
		return
	}

	if currentSize >= warningThreshold90 && !rl.criticalWarned.Load() {
		rl.criticalWarned.Store(true)
		rl.logger.Warn("rate limiter at critical capacity",
			slog.Int64("entries", currentSize),
			slog.Int64("max", maxRateLimiterEntries),
			slog.Float64("percent", float64(currentSize)/float64(maxRateLimiterEntries)*100),
		)
	} else if currentSize >= warningThreshold80 && !rl.capacityWarned.Load() {
		rl.capacityWarned.Store(true)
		rl.logger.Warn("rate limiter approaching capacity",
			slog.Int64("entries", currentSize),
			slog.Int64("max", maxRateLimiterEntries),
			slog.Float64("percent", float64(currentSize)/float64(maxRateLimiterEntries)*100),
		)
	}
}

// getSubnetLimiter returns a rate limiter for the IP's subnet (fallback when at capacity).
// Uses /24 for IPv4 and /64 for IPv6.
func (rl *IPRateLimiter) getSubnetLimiter(ip string) *rate.Limiter {
	subnet := rl.ipToSubnet(ip)

	// Try to get existing subnet limiter
	if val, ok := rl.subnetLimiters.Load(subnet); ok {
		entry := val.(*rateLimiterEntry)
		entry.mu.Lock()
		entry.lastAccess = time.Now()
		entry.mu.Unlock()
		return entry.limiter
	}

	// Check subnet limiter capacity
	if rl.subnetSize.Load() >= maxSubnetLimiterEntries {
		return nil // True fail-closed only when both are at capacity
	}

	// Subnet limiter with lower rate (shared across IPs in subnet)
	// Use 1/4 rate and 1/2 burst since multiple IPs share it
	subnetRate := rl.rate / 4
	subnetBurst := max(rl.burst/2, 1)

	entry := &rateLimiterEntry{
		limiter:    rate.NewLimiter(subnetRate, subnetBurst),
		lastAccess: time.Now(),
	}

	actual, loaded := rl.subnetLimiters.LoadOrStore(subnet, entry)
	if !loaded {
		rl.subnetSize.Add(1)
	}
	return actual.(*rateLimiterEntry).limiter
}

// ipToSubnet converts an IP to its subnet representation.
// IPv4: /24 subnet, IPv6: /64 subnet.
func (rl *IPRateLimiter) ipToSubnet(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ip // Fallback to full IP if parsing fails
	}

	if parsed.To4() != nil {
		// IPv4: /24 subnet
		return parsed.Mask(net.CIDRMask(24, 32)).String()
	}
	// IPv6: /64 subnet
	return parsed.Mask(net.CIDRMask(64, 128)).String()
}

// cleanupLoop removes stale rate limiters that haven't been accessed recently.
func (rl *IPRateLimiter) cleanupLoop() {
	const maxAge = 10 * time.Minute

	for {
		select {
		case <-rl.cleanup.C:
			now := time.Now()

			// Cleanup main IP limiters
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

			// Cleanup subnet limiters
			rl.subnetLimiters.Range(func(key, value any) bool {
				entry := value.(*rateLimiterEntry)
				entry.mu.Lock()
				age := now.Sub(entry.lastAccess)
				entry.mu.Unlock()

				if age > maxAge {
					rl.subnetLimiters.Delete(key)
					rl.subnetSize.Add(-1)
				}
				return true
			})

			// Reset warning flags after cleanup if below thresholds
			currentSize := rl.size.Load()
			if currentSize < warningThreshold80 {
				rl.capacityWarned.Store(false)
				rl.criticalWarned.Store(false)
			} else if currentSize < warningThreshold90 {
				rl.criticalWarned.Store(false)
			}

		case <-rl.done:
			return
		}
	}
}

// Stop stops the cleanup goroutine.
func (rl *IPRateLimiter) Stop() {
	rl.cleanup.Stop()
	close(rl.done)
}

// RateLimitMiddleware returns Echo middleware for rate limiting.
func (rl *IPRateLimiter) RateLimitMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ip := c.RealIP()
			limiter := rl.getLimiter(ip)

			// If limiter is nil, we're at capacity - fail closed
			if limiter == nil || !limiter.Allow() {
				return c.JSON(http.StatusTooManyRequests, ErrorResponse{
					Error: ErrorDetail{
						Code:    "RATE_LIMITED",
						Message: "Too many requests",
					},
				})
			}

			return next(c)
		}
	}
}
