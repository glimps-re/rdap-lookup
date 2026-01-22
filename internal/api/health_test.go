package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/glimps-re/rdap-lookup/internal/cache"
)

func TestHealthChecker_SetReady(t *testing.T) {
	h := NewHealthChecker()

	// Initial state should be not ready
	if h.IsReady() {
		t.Error("initial state should be not ready")
	}

	// Set to ready
	h.SetReady(true)
	if !h.IsReady() {
		t.Error("expected ready after SetReady(true)")
	}

	// Set back to not ready
	h.SetReady(false)
	if h.IsReady() {
		t.Error("expected not ready after SetReady(false)")
	}
}

func TestHealthChecker_ReadinessHandler_NotReady(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	h := NewHealthChecker()
	// h.SetReady(false) - default is not ready

	err := h.ReadinessHandler(c)
	if err != nil {
		t.Fatalf("ReadinessHandler returned error: %v", err)
	}

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status code = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}

	var status HealthStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if status.Status != "not ready" {
		t.Errorf("status = %q, want %q", status.Status, "not ready")
	}
}

func TestHealthChecker_ReadinessHandler_Ready(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	h := NewHealthChecker()
	h.SetReady(true)

	err := h.ReadinessHandler(c)
	if err != nil {
		t.Fatalf("ReadinessHandler returned error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rec.Code, http.StatusOK)
	}

	var status HealthStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if status.Status != "ready" {
		t.Errorf("status = %q, want %q", status.Status, "ready")
	}
}

func TestHealthChecker_LivenessHandler(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	h := NewHealthChecker()

	err := h.LivenessHandler(c)
	if err != nil {
		t.Fatalf("LivenessHandler returned error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rec.Code, http.StatusOK)
	}

	var status HealthStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if status.Status != "healthy" {
		t.Errorf("status = %q, want %q", status.Status, "healthy")
	}
}

func TestHealthChecker_Concurrent(t *testing.T) {
	h := NewHealthChecker()

	// Test concurrent access
	done := make(chan struct{})
	for i := range 100 {
		go func(ready bool) {
			h.SetReady(ready)
			_ = h.IsReady()
		}(i%2 == 0)
	}

	// Wait for goroutines (simple approach, not perfect)
	for range 100 {
		go func() {
			_ = h.IsReady()
			done <- struct{}{}
		}()
	}

	for range 100 {
		<-done
	}
}

// mockL2Cache implements cache.L2Cache for testing.
type mockL2Cache struct {
	pingErr error
}

func (m *mockL2Cache) Get(_ context.Context, _ string) (*cache.Entry, error) {
	return nil, cache.ErrCacheMiss
}

func (m *mockL2Cache) Set(_ context.Context, _ string, _ []byte, _ time.Duration, _ bool) error {
	return nil
}

func (m *mockL2Cache) Delete(_ context.Context, _ string) error {
	return nil
}

func (m *mockL2Cache) Clear(_ context.Context) error {
	return nil
}

func (m *mockL2Cache) Stats() cache.Stats {
	return cache.Stats{}
}

func (m *mockL2Cache) Close() error {
	return nil
}

func (m *mockL2Cache) IsAvailable(_ context.Context) bool {
	return m.pingErr == nil
}

func (m *mockL2Cache) Ping(_ context.Context) error {
	return m.pingErr
}

func TestHealthChecker_ReadinessHandler_WithL2CacheHealthy(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	h := NewHealthChecker()
	h.SetReady(true)
	h.SetL2Cache(&mockL2Cache{pingErr: nil})

	err := h.ReadinessHandler(c)
	if err != nil {
		t.Fatalf("ReadinessHandler returned error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rec.Code, http.StatusOK)
	}

	var status HealthStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if status.Status != "ready" {
		t.Errorf("status = %q, want %q", status.Status, "ready")
	}

	if status.L2CacheStatus != "healthy" {
		t.Errorf("l2_cache_status = %q, want %q", status.L2CacheStatus, "healthy")
	}
}

func TestHealthChecker_ReadinessHandler_WithL2CacheDegraded(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	h := NewHealthChecker()
	h.SetReady(true)
	h.SetL2Cache(&mockL2Cache{pingErr: errors.New("connection refused")})

	err := h.ReadinessHandler(c)
	if err != nil {
		t.Fatalf("ReadinessHandler returned error: %v", err)
	}

	// Should still return 200 OK (warn only, don't fail)
	if rec.Code != http.StatusOK {
		t.Errorf("status code = %d, want %d", rec.Code, http.StatusOK)
	}

	var status HealthStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if status.Status != "ready" {
		t.Errorf("status = %q, want %q", status.Status, "ready")
	}

	if status.L2CacheStatus != "degraded" {
		t.Errorf("l2_cache_status = %q, want %q", status.L2CacheStatus, "degraded")
	}
}

func TestHealthChecker_SetLogger(t *testing.T) {
	h := NewHealthChecker()
	logger := slog.New(slog.DiscardHandler)
	h.SetLogger(logger)

	// Verify logger was set by calling a method that uses it
	h.SetReady(true)
	h.SetL2Cache(&mockL2Cache{pingErr: errors.New("test error")})

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Should not panic with custom logger
	err := h.ReadinessHandler(c)
	if err != nil {
		t.Fatalf("ReadinessHandler returned error: %v", err)
	}
}
