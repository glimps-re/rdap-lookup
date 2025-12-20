package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/glimps-re/rdap-lookup/pkg/rdaplookup"
)

// ClientMode represents the RDAP client mode.
type ClientMode string

const (
	// ModeStandalone uses direct RDAP queries with embedded bootstrap.
	ModeStandalone ClientMode = "standalone"
	// ModeServer uses the rdap-lookup REST API server.
	ModeServer ClientMode = "server"
)

// AnalysisConfig holds analyzer configuration.
type AnalysisConfig struct {
	Count     int
	Timeout   time.Duration
	CacheSize int64
	CacheTTL  time.Duration
	NoCache   bool
	IPLookup  bool
	ASNLookup bool
	Verbose   bool

	// Client mode
	ServerURL string // If set, use server mode; otherwise standalone
}

// Mode returns the client mode based on configuration.
func (c AnalysisConfig) Mode() ClientMode {
	if c.ServerURL != "" {
		return ModeServer
	}
	return ModeStandalone
}

// LookupResult holds the result of a single domain lookup.
type LookupResult struct {
	Domain    string
	SourceURL string
	Response  *rdaplookup.DomainResponse
	Error     error
	Duration  time.Duration
	Cached    bool
	Timestamp time.Time
}

// IPLookupResult holds the result of an IP lookup.
type IPLookupResult struct {
	IP       string
	Domain   string
	Response *rdaplookup.IPResponse
	Error    error
	Duration time.Duration
}

// AnalysisReport contains all analysis results.
type AnalysisReport struct {
	// Metadata
	GeneratedAt       time.Time
	PhishingURLCount  int
	UniqueDomainCount int

	// Client mode
	ClientMode ClientMode
	ServerURL  string // Only set if using server mode

	// Timing
	BootstrapDuration time.Duration
	TotalDuration     time.Duration

	// Library info
	CacheSize    int64
	CacheTTL     time.Duration
	CacheEnabled bool

	// Results
	DomainResults []LookupResult
	IPResults     []IPLookupResult

	// Raw data
	PhishingEntries []PhishingEntry

	// Errors
	FetchError error
}

// Analyzer performs the analysis.
type Analyzer struct {
	config     AnalysisConfig
	phishStats *PhishStatsClient
	rdapClient rdaplookup.RDAPClient
	logger     *slog.Logger
}

// NewAnalyzer creates a new analyzer.
func NewAnalyzer(config AnalysisConfig, logger *slog.Logger) *Analyzer {
	return &Analyzer{
		config:     config,
		phishStats: NewPhishStatsClient(),
		logger:     logger,
	}
}

// Run performs the full analysis.
func (a *Analyzer) Run(ctx context.Context) (*AnalysisReport, error) {
	report := &AnalysisReport{
		GeneratedAt:  time.Now().UTC(),
		CacheSize:    a.config.CacheSize,
		CacheTTL:     a.config.CacheTTL,
		CacheEnabled: !a.config.NoCache,
		ClientMode:   a.config.Mode(),
		ServerURL:    a.config.ServerURL,
	}

	startTime := time.Now()

	// Step 1: Fetch phishing URLs
	a.logger.Info("fetching phishing URLs from PhishStats",
		"count", a.config.Count)

	entries, err := a.phishStats.FetchPhishingURLs(ctx, a.config.Count)
	if err != nil {
		report.FetchError = err
		return report, err
	}
	report.PhishingEntries = entries
	report.PhishingURLCount = len(entries)

	a.logger.Info("fetched phishing URLs",
		"count", len(entries))

	// Step 2: Extract unique domains
	domains := a.extractUniqueDomains(entries)
	report.UniqueDomainCount = len(domains)

	a.logger.Info("extracted unique domains",
		"unique", len(domains))

	// Step 3: Initialize RDAP client based on mode
	bootstrapStart := time.Now()

	//nolint:contextcheck // createClient calls NewStandaloneClient which is a constructor
	client, err := a.createClient()
	if err != nil {
		return report, err
	}
	defer func() { _ = client.Close() }()
	a.rdapClient = client

	report.BootstrapDuration = time.Since(bootstrapStart)
	a.logger.Info("RDAP client initialized",
		"mode", a.config.Mode(),
		"bootstrap_duration", report.BootstrapDuration)

	// Step 4: Perform domain lookups
	report.DomainResults = a.lookupDomains(ctx, domains)

	// Step 5: Perform IP lookups if enabled
	if a.config.IPLookup {
		report.IPResults = a.lookupIPs(ctx, entries)
	}

	report.TotalDuration = time.Since(startTime)

	return report, nil
}

// createClient creates the appropriate RDAP client based on configuration.
func (a *Analyzer) createClient() (rdaplookup.RDAPClient, error) {
	if a.config.ServerURL != "" {
		// Server mode - use REST API client
		a.logger.Info("using server mode",
			"server", a.config.ServerURL)

		client, err := rdaplookup.NewClient(
			a.config.ServerURL,
			rdaplookup.WithTimeout(a.config.Timeout),
		)
		if err != nil {
			return nil, fmt.Errorf("create REST API client: %w", err)
		}
		return client, nil
	}

	// Standalone mode - use embedded bootstrap and cache
	a.logger.Info("using standalone mode")

	opts := []rdaplookup.StandaloneOption{
		rdaplookup.WithStandaloneTimeout(a.config.Timeout),
		rdaplookup.WithCacheSize(a.config.CacheSize),
		rdaplookup.WithCacheTTL(a.config.CacheTTL),
		rdaplookup.WithStandaloneLogger(a.logger),
	}

	if a.config.NoCache {
		opts = append(opts, rdaplookup.WithoutCache())
	}

	client, err := rdaplookup.NewStandaloneClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("create standalone client: %w", err)
	}
	return client, nil
}

// extractUniqueDomains extracts and deduplicates domains from phishing URLs.
func (a *Analyzer) extractUniqueDomains(entries []PhishingEntry) map[string]string {
	domains := make(map[string]string) // domain -> first source URL

	for _, entry := range entries {
		parsed, err := url.Parse(entry.URL)
		if err != nil {
			continue
		}

		host := strings.ToLower(parsed.Hostname())
		if host == "" {
			continue
		}

		// Normalize to registrable domain
		normalized := rdaplookup.NormalizeDomain(host)
		if normalized == "" {
			normalized = host
		}

		// Skip IP addresses
		if isIPAddress(normalized) {
			continue
		}

		if _, exists := domains[normalized]; !exists {
			domains[normalized] = entry.URL
		}
	}

	return domains
}

// lookupDomains performs RDAP lookups for all domains.
func (a *Analyzer) lookupDomains(ctx context.Context, domains map[string]string) []LookupResult {
	results := make([]LookupResult, 0, len(domains))

	for domain, sourceURL := range domains {
		start := time.Now()

		resp, err := a.rdapClient.LookupDomain(ctx, domain)

		duration := time.Since(start)

		result := LookupResult{
			Domain:    domain,
			SourceURL: sourceURL,
			Response:  resp,
			Error:     err,
			Duration:  duration,
			Timestamp: time.Now().UTC(),
		}

		if resp != nil {
			result.Cached = resp.Cached
		}

		results = append(results, result)

		if a.config.Verbose {
			status := "OK"
			if err != nil {
				status = err.Error()
			}
			a.logger.Info("domain lookup",
				"domain", domain,
				"duration", duration,
				"status", status,
				"cached", result.Cached)
		}
	}

	return results
}

// lookupIPs performs RDAP lookups for IPs from phishing entries.
func (a *Analyzer) lookupIPs(ctx context.Context, entries []PhishingEntry) []IPLookupResult {
	// Deduplicate IPs
	ips := make(map[string]string) // IP -> domain
	for _, entry := range entries {
		if entry.IP != "" && !strings.HasPrefix(entry.IP, "0.") {
			if _, exists := ips[entry.IP]; !exists {
				// Extract domain from URL
				parsed, _ := url.Parse(entry.URL)
				if parsed != nil {
					ips[entry.IP] = parsed.Hostname()
				}
			}
		}
	}

	results := make([]IPLookupResult, 0, len(ips))

	for ip, domain := range ips {
		start := time.Now()
		resp, err := a.rdapClient.LookupIP(ctx, ip)
		duration := time.Since(start)

		results = append(results, IPLookupResult{
			IP:       ip,
			Domain:   domain,
			Response: resp,
			Error:    err,
			Duration: duration,
		})

		if a.config.Verbose {
			status := "OK"
			if err != nil {
				status = err.Error()
			}
			a.logger.Info("IP lookup",
				"ip", ip,
				"duration", duration,
				"status", status)
		}
	}

	return results
}

func isIPAddress(s string) bool {
	// Simple check - contains only digits, dots, colons, and hex chars
	for _, r := range s {
		if r != '.' && r != ':' && (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return strings.Contains(s, ".") || strings.Contains(s, ":")
}
