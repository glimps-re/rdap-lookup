// Package logging provides structured logging setup using slog.
package logging

import (
	"io"
	"log/slog"
	"os"
)

// Config holds logging configuration.
type Config struct {
	// Level is the log level: debug, info, warn, error.
	Level string
	// Format is the log format: json, text.
	Format string
}

// Setup initializes the global slog logger with the given configuration.
// It returns the configured logger for use with Echo or other components.
func Setup(cfg Config) *slog.Logger {
	return SetupWithWriter(cfg, os.Stdout)
}

// SetupWithWriter initializes the logger with a custom writer.
// This is useful for testing.
func SetupWithWriter(cfg Config, w io.Writer) *slog.Logger {
	level := parseLevel(cfg.Level)

	opts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	if cfg.Format == "text" {
		handler = slog.NewTextHandler(w, opts)
	} else {
		handler = slog.NewJSONHandler(w, opts)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)

	return logger
}

// parseLevel converts a string log level to slog.Level.
func parseLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// WithComponent returns a logger with the component attribute set.
func WithComponent(logger *slog.Logger, component string) *slog.Logger {
	return logger.With(slog.String("component", component))
}

// WithRequestID returns a logger with the request_id attribute set.
func WithRequestID(logger *slog.Logger, requestID string) *slog.Logger {
	return logger.With(slog.String("request_id", requestID))
}
