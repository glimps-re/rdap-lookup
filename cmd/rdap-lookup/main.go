// Package main provides the entry point for the rdap-lookup service.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/glimps-re/rdap-lookup/internal/api"
	"github.com/glimps-re/rdap-lookup/internal/bootstrap"
	"github.com/glimps-re/rdap-lookup/internal/cache"
	"github.com/glimps-re/rdap-lookup/internal/config"
	"github.com/glimps-re/rdap-lookup/internal/logging"
	"github.com/glimps-re/rdap-lookup/internal/metrics"
	"github.com/glimps-re/rdap-lookup/internal/rdap"
)

// Build information set at build time via ldflags.
var (
	Version   = "dev"
	GitCommit = "unknown"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Setup logging
	logger := logging.Setup(logging.Config{
		Level:  cfg.Log.Level,
		Format: cfg.Log.Format,
	})

	logger.Info("starting rdap-lookup",
		slog.String("version", Version),
	)

	// Setup metrics
	m := metrics.New()
	m.MustRegister()

	// Initialize bootstrap service
	bs := bootstrap.NewService(
		cfg.Bootstrap.RefreshInterval,
		cfg.RDAP.Timeout, // Use RDAP timeout for fetching bootstrap data
		logger,
		m,
	)

	// Load bootstrap data
	ctx := context.Background()
	if err := bs.Start(ctx); err != nil {
		return fmt.Errorf("failed to start bootstrap service: %w", err)
	}
	defer bs.Stop()

	// Initialize RDAP client
	rdapClient := rdap.NewClient(
		cfg.RDAP.Timeout,
		rdap.WithMaxRetries(cfg.RDAP.MaxRetries),
		rdap.WithUserAgent("rdap-lookup/"+Version),
		rdap.WithLogger(logger),
		rdap.WithMetrics(m),
		rdap.WithResolver(bs.Resolver()),
	)

	// Initialize cache
	cacheConfig := cache.TieredCacheConfig{
		L1Config: cache.MemoryCacheConfig{
			MaxEntries: 10000,
			MaxSize:    cfg.Cache.RAM.MaxSize,
		},
		DefaultTTL:     cfg.Cache.TTL,
		NegativeTTL:    cfg.Cache.NegativeTTL,
		L1PromotionTTL: 5 * 60 * 1000000000, // 5 minutes in nanoseconds
		EnableL2Writes: true,
	}

	// Configure Redis if enabled
	if cfg.Cache.Redis.Enabled {
		cacheConfig.L2Config = &cache.RedisCacheConfig{
			Addr:     cfg.Cache.Redis.Addr,
			Password: cfg.Cache.Redis.Password,
			DB:       cfg.Cache.Redis.DB,
		}
	}

	tieredCache, err := cache.NewTieredCache(cacheConfig)
	if err != nil {
		return fmt.Errorf("failed to create cache: %w", err)
	}
	defer func() { _ = tieredCache.Close() }()

	// Wire up cache metrics
	tieredCache.SetMetrics(metrics.NewCacheMetricsCollector(m))

	// Create lookup handler (with optional WHOIS fallback)
	// handlerTimeout mirrors Server.WriteTimeout so per-handler deadlines
	// cancel upstream I/O before the HTTP connection deadline elapses.
	var lookupHandler *api.LookupHandler
	if cfg.WHOIS.Enabled {
		logger.Info("WHOIS fallback enabled",
			slog.Duration("timeout", cfg.WHOIS.Timeout),
			slog.Int64("max_response_size", cfg.WHOIS.MaxResponseSize),
		)
		lookupHandler = api.NewLookupHandlerWithWHOIS(rdapClient, bs, tieredCache, cfg.Batch, cfg.Server.WriteTimeout, cfg.WHOIS, m)
	} else {
		lookupHandler = api.NewLookupHandler(rdapClient, bs, tieredCache, cfg.Batch, cfg.Server.WriteTimeout, m)
	}
	defer func() { _ = lookupHandler.Close() }()

	// Create server with build info and dependencies
	buildInfo := api.BuildInfo{
		Version:   Version,
		GitCommit: GitCommit,
	}
	deps := &api.ServerDeps{
		LookupHandler: lookupHandler,
	}
	server := api.NewServer(cfg, logger, m, buildInfo, deps)

	// Start server in goroutine
	serverErr := make(chan error, 1)
	go func() {
		if err := server.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
		close(serverErr)
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-quit:
		logger.Info("received shutdown signal")
	case err := <-serverErr:
		if err != nil {
			return fmt.Errorf("server error: %w", err)
		}
	}

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown error: %w", err)
	}

	logger.Info("server stopped")
	return nil
}
