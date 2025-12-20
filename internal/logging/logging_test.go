package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestSetup_JSONFormat(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{Level: "info", Format: "json"}

	logger := SetupWithWriter(cfg, &buf)
	logger.Info("test message", slog.String("key", "value"))

	output := buf.String()
	if output == "" {
		t.Fatal("expected log output, got empty string")
	}

	// Verify it's valid JSON
	var logEntry map[string]interface{}
	if err := json.Unmarshal([]byte(output), &logEntry); err != nil {
		t.Fatalf("log output is not valid JSON: %v", err)
	}

	if logEntry["msg"] != "test message" {
		t.Errorf("msg = %v, want 'test message'", logEntry["msg"])
	}
	if logEntry["key"] != "value" {
		t.Errorf("key = %v, want 'value'", logEntry["key"])
	}
}

func TestSetup_TextFormat(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{Level: "info", Format: "text"}

	logger := SetupWithWriter(cfg, &buf)
	logger.Info("test message", slog.String("key", "value"))

	output := buf.String()
	if output == "" {
		t.Fatal("expected log output, got empty string")
	}

	// Text format should not be JSON
	var logEntry map[string]interface{}
	if err := json.Unmarshal([]byte(output), &logEntry); err == nil {
		t.Error("expected text format, got valid JSON")
	}

	if !strings.Contains(output, "test message") {
		t.Errorf("output should contain 'test message', got: %s", output)
	}
}

func TestSetup_LogLevels(t *testing.T) {
	tests := []struct {
		level       string
		logFunc     func(*slog.Logger)
		shouldLog   bool
		messageText string
	}{
		{
			level:       "debug",
			logFunc:     func(l *slog.Logger) { l.Debug("debug msg") },
			shouldLog:   true,
			messageText: "debug msg",
		},
		{
			level:       "info",
			logFunc:     func(l *slog.Logger) { l.Debug("debug msg") },
			shouldLog:   false,
			messageText: "debug msg",
		},
		{
			level:       "info",
			logFunc:     func(l *slog.Logger) { l.Info("info msg") },
			shouldLog:   true,
			messageText: "info msg",
		},
		{
			level:       "warn",
			logFunc:     func(l *slog.Logger) { l.Info("info msg") },
			shouldLog:   false,
			messageText: "info msg",
		},
		{
			level:       "warn",
			logFunc:     func(l *slog.Logger) { l.Warn("warn msg") },
			shouldLog:   true,
			messageText: "warn msg",
		},
		{
			level:       "error",
			logFunc:     func(l *slog.Logger) { l.Warn("warn msg") },
			shouldLog:   false,
			messageText: "warn msg",
		},
		{
			level:       "error",
			logFunc:     func(l *slog.Logger) { l.Error("error msg") },
			shouldLog:   true,
			messageText: "error msg",
		},
	}

	for _, tt := range tests {
		t.Run(tt.level+"_"+tt.messageText, func(t *testing.T) {
			var buf bytes.Buffer
			cfg := Config{Level: tt.level, Format: "json"}

			logger := SetupWithWriter(cfg, &buf)
			tt.logFunc(logger)

			output := buf.String()
			hasOutput := strings.Contains(output, tt.messageText)

			if hasOutput != tt.shouldLog {
				t.Errorf("level=%s, message=%s: expected shouldLog=%v, got output=%v",
					tt.level, tt.messageText, tt.shouldLog, hasOutput)
			}
		})
	}
}

func TestWithComponent(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{Level: "info", Format: "json"}

	logger := SetupWithWriter(cfg, &buf)
	compLogger := WithComponent(logger, "test-component")
	compLogger.Info("test message")

	output := buf.String()

	var logEntry map[string]interface{}
	if err := json.Unmarshal([]byte(output), &logEntry); err != nil {
		t.Fatalf("log output is not valid JSON: %v", err)
	}

	if logEntry["component"] != "test-component" {
		t.Errorf("component = %v, want 'test-component'", logEntry["component"])
	}
}

func TestWithRequestID(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{Level: "info", Format: "json"}

	logger := SetupWithWriter(cfg, &buf)
	reqLogger := WithRequestID(logger, "req-12345")
	reqLogger.Info("test message")

	output := buf.String()

	var logEntry map[string]interface{}
	if err := json.Unmarshal([]byte(output), &logEntry); err != nil {
		t.Fatalf("log output is not valid JSON: %v", err)
	}

	if logEntry["request_id"] != "req-12345" {
		t.Errorf("request_id = %v, want 'req-12345'", logEntry["request_id"])
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input string
		want  slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"error", slog.LevelError},
		{"invalid", slog.LevelInfo}, // default
		{"", slog.LevelInfo},        // default
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseLevel(tt.input)
			if got != tt.want {
				t.Errorf("parseLevel(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
