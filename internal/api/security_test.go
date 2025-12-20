package api

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestLogSecurityEvent(t *testing.T) {
	tests := []struct {
		name         string
		event        SecurityEvent
		wantContains []string
	}{
		{
			name: "basic event",
			event: SecurityEvent{
				Type:     SecurityEventValidationFailed,
				RemoteIP: "192.168.1.1",
				Path:     "/domain/test",
			},
			wantContains: []string{
				"security event",
				"validation_failed",
				"192.168.1.1",
				"/domain/test",
			},
		},
		{
			name: "event with request ID",
			event: SecurityEvent{
				Type:      SecurityEventRateLimited,
				RequestID: "req-12345",
				RemoteIP:  "10.0.0.1",
				Path:      "/batch",
			},
			wantContains: []string{
				"rate_limited",
				"req-12345",
				"10.0.0.1",
			},
		},
		{
			name: "event with details",
			event: SecurityEvent{
				Type:     SecurityEventSSRFBlocked,
				RemoteIP: "127.0.0.1",
				Path:     "/entity/test",
				Details: map[string]string{
					"blocked_url": "https://evil.com",
					"reason":      "not in allowlist",
				},
			},
			wantContains: []string{
				"ssrf_blocked",
				"blocked_url",
				"https://evil.com",
				"reason",
				"not in allowlist",
			},
		},
		{
			name: "invalid server event",
			event: SecurityEvent{
				Type:     SecurityEventInvalidServer,
				RemoteIP: "172.16.0.1",
				Path:     "/entity/handle",
				Details: map[string]string{
					"server": "http://internal.local",
				},
			},
			wantContains: []string{
				"invalid_server",
				"http://internal.local",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, nil))

			LogSecurityEvent(logger, nil, tt.event)

			output := buf.String()
			for _, want := range tt.wantContains {
				if !strings.Contains(output, want) {
					t.Errorf("log output should contain %q, got: %s", want, output)
				}
			}
		})
	}
}

func TestSecurityEventTypes(t *testing.T) {
	// Verify all event type constants are defined correctly
	tests := []struct {
		eventType SecurityEventType
		expected  string
	}{
		{SecurityEventValidationFailed, "validation_failed"},
		{SecurityEventRateLimited, "rate_limited"},
		{SecurityEventSSRFBlocked, "ssrf_blocked"},
		{SecurityEventInvalidServer, "invalid_server"},
	}

	for _, tt := range tests {
		t.Run(string(tt.eventType), func(t *testing.T) {
			if string(tt.eventType) != tt.expected {
				t.Errorf("event type = %q, want %q", string(tt.eventType), tt.expected)
			}
		})
	}
}

func TestSecurityEvent_EmptyRequestID(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	event := SecurityEvent{
		Type:      SecurityEventValidationFailed,
		RequestID: "", // Empty request ID should not be logged
		RemoteIP:  "192.168.1.1",
		Path:      "/test",
	}

	LogSecurityEvent(logger, nil, event)

	output := buf.String()
	// Should not contain request_id attribute when empty
	if strings.Contains(output, "request_id=") {
		t.Errorf("log output should not contain request_id when empty, got: %s", output)
	}
}

func TestSecurityEvent_EmptyDetails(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	event := SecurityEvent{
		Type:     SecurityEventValidationFailed,
		RemoteIP: "192.168.1.1",
		Path:     "/test",
		Details:  nil, // No details
	}

	LogSecurityEvent(logger, nil, event)

	output := buf.String()
	// Should still log the basic event
	if !strings.Contains(output, "security event") {
		t.Errorf("log output should contain 'security event', got: %s", output)
	}
}
