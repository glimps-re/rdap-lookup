// Package main provides a debug tool for testing the rdap-lookup library
// by analyzing phishing domains from PhishStats.info.
//
// Usage:
//
//	phishstats-analyzer [flags]
//
// Flags:
//
//	-n, --count int           Number of phishing URLs to fetch (default 50)
//	-o, --output string       Output file path (default "tmp/phishstats_report.md")
//	-t, --timeout duration    RDAP lookup timeout (default 10s)
//	-s, --server string       Use REST API server base URL (e.g., http://localhost:8080)
//	--cache-size int          Cache size in MB (default 50, standalone only)
//	--no-cache                Disable caching (standalone only)
//	--ip-lookup               Also perform IP lookups
//	-v, --verbose             Verbose output
//	--version                 Show version
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	// Parse flags
	var config AnalysisConfig
	var outputPath string
	var showVersion bool
	var cacheSizeMB int

	flag.IntVar(&config.Count, "n", 50, "Number of phishing URLs to fetch")
	flag.IntVar(&config.Count, "count", 50, "Number of phishing URLs to fetch")
	flag.StringVar(&outputPath, "o", "tmp/phishstats_report.md", "Output file path")
	flag.StringVar(&outputPath, "output", "tmp/phishstats_report.md", "Output file path")
	flag.DurationVar(&config.Timeout, "t", 10*time.Second, "RDAP lookup timeout")
	flag.DurationVar(&config.Timeout, "timeout", 10*time.Second, "RDAP lookup timeout")
	flag.StringVar(&config.ServerURL, "s", "", "Use REST API server base URL (e.g., http://localhost:8080)")
	flag.StringVar(&config.ServerURL, "server", "", "Use REST API server base URL (e.g., http://localhost:8080)")
	flag.IntVar(&cacheSizeMB, "cache-size", 50, "Cache size in MB (standalone mode only)")
	flag.DurationVar(&config.CacheTTL, "cache-ttl", 24*time.Hour, "Cache TTL (standalone mode only)")
	flag.BoolVar(&config.NoCache, "no-cache", false, "Disable caching (standalone mode only)")
	flag.BoolVar(&config.IPLookup, "ip-lookup", false, "Also perform IP lookups")
	flag.BoolVar(&config.ASNLookup, "asn-lookup", false, "Also perform ASN lookups")
	flag.BoolVar(&config.Verbose, "v", false, "Verbose output")
	flag.BoolVar(&config.Verbose, "verbose", false, "Verbose output")
	flag.BoolVar(&showVersion, "version", false, "Show version")

	flag.Parse()

	if showVersion {
		fmt.Printf("phishstats-analyzer %s\n", version)
		return 0
	}

	// Convert MB to bytes
	config.CacheSize = int64(cacheSizeMB) * 1024 * 1024

	// Setup logger
	logLevel := slog.LevelInfo
	if config.Verbose {
		logLevel = slog.LevelDebug
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	}))

	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Info("received shutdown signal, cancelling...")
		cancel()
	}()

	// Clean and validate output path
	cleanedOutputPath := filepath.Clean(outputPath)

	// Ensure output directory exists
	outputDir := filepath.Dir(cleanedOutputPath)
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		logger.Error("failed to create output directory", "error", err)
		return 1
	}

	// Run analysis
	analyzer := NewAnalyzer(config, logger)

	mode := "standalone"
	if config.ServerURL != "" {
		mode = "server (" + config.ServerURL + ")"
	}

	logger.Info("starting PhishStats analysis",
		"count", config.Count,
		"output", cleanedOutputPath,
		"mode", mode,
		"cache_enabled", !config.NoCache)

	report, err := analyzer.Run(ctx)
	if err != nil {
		logger.Error("analysis failed", "error", err)
		return 1
	}

	// Generate report
	file, err := os.Create(cleanedOutputPath) //#nosec G304 -- user-provided output path is intentional
	if err != nil {
		logger.Error("failed to create output file", "error", err)
		return 1
	}
	defer func() { _ = file.Close() }()

	generator := &ReportGenerator{}
	if err := generator.Generate(file, report); err != nil {
		logger.Error("failed to generate report", "error", err)
		return 1
	}

	logger.Info("analysis complete",
		"output", cleanedOutputPath,
		"mode", string(report.ClientMode),
		"domains", report.UniqueDomainCount,
		"success", countSuccess(report.DomainResults),
		"errors", countErrors(report.DomainResults),
		"duration", report.TotalDuration.Round(time.Millisecond))

	fmt.Printf("\nReport written to: %s\n", cleanedOutputPath)
	return 0
}

func countSuccess(results []LookupResult) int {
	count := 0
	for _, r := range results {
		if r.Error == nil {
			count++
		}
	}
	return count
}

func countErrors(results []LookupResult) int {
	count := 0
	for _, r := range results {
		if r.Error != nil {
			count++
		}
	}
	return count
}
