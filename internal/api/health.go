// Package api provides HTTP handlers and routing for the rdap-lookup service.
package api

import (
	"context"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/glimps-re/rdap-lookup/internal/cache"
)

// HealthChecker provides health check functionality for the service.
type HealthChecker struct {
	ready   atomic.Bool
	l2Cache cache.L2Cache
	logger  *slog.Logger
}

// NewHealthChecker creates a new HealthChecker.
func NewHealthChecker() *HealthChecker {
	return &HealthChecker{
		logger: slog.Default(),
	}
}

// SetL2Cache sets the L2 cache for health checking.
func (h *HealthChecker) SetL2Cache(l2 cache.L2Cache) {
	h.l2Cache = l2
}

// SetLogger sets the logger for the health checker.
func (h *HealthChecker) SetLogger(logger *slog.Logger) {
	h.logger = logger
}

// SetReady sets the readiness state of the service.
func (h *HealthChecker) SetReady(ready bool) {
	h.ready.Store(ready)
}

// IsReady returns true if the service is ready to accept traffic.
func (h *HealthChecker) IsReady() bool {
	return h.ready.Load()
}

// HealthStatus represents the health check response.
type HealthStatus struct {
	Status        string `json:"status"`
	L2CacheStatus string `json:"l2_cache_status,omitempty"`
}

// ReadinessHandler handles the /ready endpoint.
// Returns 200 OK when the service is ready to accept traffic.
// Returns 503 Service Unavailable when not ready.
// L2 cache health is checked but only warns on failure (doesn't fail readiness).
func (h *HealthChecker) ReadinessHandler(c echo.Context) error {
	if !h.IsReady() {
		return c.JSON(http.StatusServiceUnavailable, HealthStatus{Status: "not ready"})
	}

	resp := HealthStatus{Status: "ready"}

	// Check L2 cache health (warn only, don't fail readiness)
	if h.l2Cache != nil {
		ctx, cancel := context.WithTimeout(c.Request().Context(), 1*time.Second)
		defer cancel()

		if err := h.l2Cache.Ping(ctx); err != nil {
			resp.L2CacheStatus = "degraded"
			h.logger.Warn("L2 cache health check failed",
				slog.String("error", err.Error()),
			)
		} else {
			resp.L2CacheStatus = "healthy"
		}
	}

	return c.JSON(http.StatusOK, resp)
}

// LivenessHandler handles the /healthz endpoint.
// Returns 200 OK when the service is alive and functioning.
func (h *HealthChecker) LivenessHandler(c echo.Context) error {
	return c.JSON(http.StatusOK, HealthStatus{Status: "healthy"})
}
