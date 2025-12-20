// Package api provides HTTP handlers and middleware for the RDAP lookup service.
package api

import (
	"log/slog"

	"github.com/glimps-re/rdap-lookup/internal/metrics"
)

// SecurityEventType represents the type of security event.
type SecurityEventType string

// Security event types.
const (
	SecurityEventValidationFailed SecurityEventType = "validation_failed"
	SecurityEventRateLimited      SecurityEventType = "rate_limited"
	SecurityEventSSRFBlocked      SecurityEventType = "ssrf_blocked"
	SecurityEventInvalidServer    SecurityEventType = "invalid_server"
)

// SecurityEvent represents a security-relevant event.
type SecurityEvent struct {
	Type      SecurityEventType
	RequestID string
	RemoteIP  string
	Path      string
	Details   map[string]string
}

// LogSecurityEvent logs a security event at WARN level and increments metrics.
func LogSecurityEvent(logger *slog.Logger, m *metrics.Metrics, event SecurityEvent) {
	attrs := []any{
		slog.String("event_type", string(event.Type)),
		slog.String("remote_ip", event.RemoteIP),
		slog.String("path", event.Path),
	}

	if event.RequestID != "" {
		attrs = append(attrs, slog.String("request_id", event.RequestID))
	}

	for k, v := range event.Details {
		attrs = append(attrs, slog.String(k, v))
	}

	logger.Warn("security event", attrs...)

	// Increment security metrics
	if m != nil && m.SecurityEventsTotal != nil {
		m.SecurityEventsTotal.WithLabelValues(string(event.Type)).Inc()
	}
}
