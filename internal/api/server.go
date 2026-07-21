package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/labstack/echo-contrib/echoprometheus"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/glimps-re/rdap-lookup/internal/config"
	"github.com/glimps-re/rdap-lookup/internal/metrics"
)

// apiV1Prefix is the prefix for all API v1 endpoints.
const apiV1Prefix = "/api/v1"

// operationalEndpoints are paths that should skip certain middleware (timeouts, rate limiting, etc).
var operationalEndpoints = map[string]bool{
	"/healthz": true,
	"/ready":   true,
	"/metrics": true,
	"/meta":    true,
}

// Server represents the HTTP server.
type Server struct {
	echo          *echo.Echo
	cfg           *config.Config
	logger        *slog.Logger
	healthChecker *HealthChecker
	metaHandler   *MetaHandler
	lookupHandler *LookupHandler
	metrics       *metrics.Metrics
	rateLimiter   *IPRateLimiter
}

// ServerDeps holds dependencies for the server.
type ServerDeps struct {
	LookupHandler *LookupHandler
}

// NewServer creates a new HTTP server.
func NewServer(cfg *config.Config, logger *slog.Logger, m *metrics.Metrics, buildInfo BuildInfo, deps *ServerDeps) *Server {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	s := &Server{
		echo:          e,
		cfg:           cfg,
		logger:        logger,
		healthChecker: NewHealthChecker(),
		metaHandler:   NewMetaHandler(buildInfo),
		metrics:       m,
	}

	// Initialize rate limiter if enabled
	if cfg.RateLimit.Enabled {
		s.rateLimiter = NewIPRateLimiter(cfg.RateLimit.RPS, cfg.RateLimit.Burst, logger, m)
	}

	if deps != nil {
		s.lookupHandler = deps.LookupHandler
	}

	s.setupMiddleware()
	s.setupRoutes()

	return s
}

// setupMiddleware configures middleware for the server.
func (s *Server) setupMiddleware() {
	// Configure IP extraction based on TrustProxy setting
	// This affects c.RealIP() used by rate limiting
	if s.cfg.Server.TrustProxy {
		s.echo.IPExtractor = echo.ExtractIPFromXFFHeader()
	} else {
		s.echo.IPExtractor = echo.ExtractIPDirect()
	}

	// Recover from panics
	s.echo.Use(middleware.Recover())

	// Security headers
	s.echo.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XSSProtection:      "1; mode=block",
		ContentTypeNosniff: "nosniff",
		XFrameOptions:      "DENY",
	}))

	// Body size limit to prevent DoS attacks
	s.echo.Use(middleware.BodyLimit(s.cfg.Server.BodyLimit))

	// Request ID middleware
	s.echo.Use(middleware.RequestID())

	// Rate limiting middleware (before other processing)
	if s.rateLimiter != nil {
		s.echo.Use(s.rateLimitMiddlewareWithLogging())
	}

	// Custom logging middleware using slog
	s.echo.Use(s.loggingMiddleware())

	// Prometheus metrics middleware (echoprometheus)
	s.echo.Use(s.prometheusMiddleware())
}

// rateLimitMiddlewareWithLogging wraps rate limiting with security event logging.
func (s *Server) rateLimitMiddlewareWithLogging() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Skip rate limiting for operational endpoints
			path := c.Request().URL.Path
			if operationalEndpoints[path] {
				return next(c)
			}

			ip := c.RealIP()
			limiter := s.rateLimiter.getLimiter(ip)

			// limiter is nil when rate limiter map is at capacity (fail-closed)
			if limiter == nil || !limiter.Allow() {
				// Log security event and increment metrics
				LogSecurityEvent(s.logger, s.metrics, SecurityEvent{
					Type:      SecurityEventRateLimited,
					RequestID: c.Response().Header().Get(echo.HeaderXRequestID),
					RemoteIP:  ip,
					Path:      path,
				})

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

// setupRoutes configures routes for the server.
func (s *Server) setupRoutes() {
	// Infrastructure endpoints (root level)
	s.echo.GET("/healthz", s.healthChecker.LivenessHandler)
	s.echo.GET("/ready", s.healthChecker.ReadinessHandler)
	s.echo.GET("/meta", s.metaHandler.Handle)
	s.echo.GET("/metrics", echoprometheus.NewHandler())

	// API v1 group for RDAP lookup endpoints
	if s.lookupHandler != nil {
		v1 := s.echo.Group(apiV1Prefix)
		v1.GET("/domain/:name", s.lookupHandler.LookupDomain)
		v1.GET("/ip/:addr", s.lookupHandler.LookupIP)
		v1.GET("/asn/:asn", s.lookupHandler.LookupASN)
		v1.GET("/entity/:handle", s.lookupHandler.LookupEntity)
		v1.POST("/batch", s.lookupHandler.LookupBatch)
	}
}

// loggingMiddleware returns a middleware that logs requests using slog.
func (s *Server) loggingMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			start := time.Now()
			req := c.Request()
			res := c.Response()

			// Get request ID
			requestID := c.Response().Header().Get(echo.HeaderXRequestID)

			err := next(c)
			if err != nil {
				c.Error(err)
			}

			duration := time.Since(start)

			// Skip logging for operational endpoints at info level
			path := req.URL.Path
			if operationalEndpoints[path] {
				s.logger.Debug("request",
					slog.String("request_id", requestID),
					slog.String("method", req.Method),
					slog.String("path", path),
					slog.Int("status", res.Status),
					slog.Duration("duration", duration),
				)
				return nil
			}

			s.logger.Info("request",
				slog.String("request_id", requestID),
				slog.String("method", req.Method),
				slog.String("path", path),
				slog.String("remote_addr", req.RemoteAddr),
				slog.Int("status", res.Status),
				slog.Int64("bytes", res.Size),
				slog.Duration("duration", duration),
			)

			return nil
		}
	}
}

// prometheusMiddleware returns the echoprometheus middleware configured for this service.
func (s *Server) prometheusMiddleware() echo.MiddlewareFunc {
	config := echoprometheus.MiddlewareConfig{
		Subsystem: "rdap",

		// Skip metrics endpoint from being counted in metrics
		Skipper: func(c echo.Context) bool {
			return c.Path() == "/metrics"
		},

		// Use Echo's route path template for URL label (prevents high cardinality)
		// This gives us "/domain/:name" instead of "/domain/example.com"
		LabelFuncs: map[string]echoprometheus.LabelValueFunc{
			"url": func(c echo.Context, err error) string {
				return c.Path()
			},
		},

		// Custom histogram buckets for request duration
		HistogramOptsFunc: func(opts prometheus.HistogramOpts) prometheus.HistogramOpts {
			if opts.Name == "request_duration_seconds" {
				opts.Buckets = []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
			}
			return opts
		},

		// Track in-flight requests using our custom metric
		BeforeNext: func(c echo.Context) {
			if s.metrics != nil {
				s.metrics.HTTPRequestsInFlight.Inc()
			}
		},
		AfterNext: func(c echo.Context, err error) {
			if s.metrics != nil {
				s.metrics.HTTPRequestsInFlight.Dec()
			}
		},
	}

	// Use ToMiddleware which doesn't panic on registration errors
	mw, err := config.ToMiddleware()
	if err != nil {
		// If middleware creation fails (e.g., metrics already registered in tests),
		// return a no-op middleware that just tracks in-flight requests
		s.logger.Warn("failed to create prometheus middleware, using fallback", "error", err)
		return func(next echo.HandlerFunc) echo.HandlerFunc {
			return func(c echo.Context) error {
				if s.metrics != nil {
					s.metrics.HTTPRequestsInFlight.Inc()
					defer s.metrics.HTTPRequestsInFlight.Dec()
				}
				return next(c)
			}
		}
	}
	return mw
}

// Start starts the HTTP server.
func (s *Server) Start() error {
	s.logger.Info("starting server",
		slog.String("addr", s.cfg.Server.ListenAddr),
	)

	server := &http.Server{
		Addr:         s.cfg.Server.ListenAddr,
		ReadTimeout:  s.cfg.Server.ReadTimeout,
		WriteTimeout: s.cfg.Server.WriteTimeout,
	}

	// Mark as ready
	s.healthChecker.SetReady(true)

	return s.echo.StartServer(server)
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("shutting down server")

	// Mark as not ready
	s.healthChecker.SetReady(false)

	// Stop rate limiter cleanup goroutine
	if s.rateLimiter != nil {
		s.rateLimiter.Stop()
	}

	return s.echo.Shutdown(ctx)
}

// Echo returns the underlying echo instance for testing.
func (s *Server) Echo() *echo.Echo {
	return s.echo
}

// HealthChecker returns the health checker for external use.
func (s *Server) HealthChecker() *HealthChecker {
	return s.healthChecker
}
