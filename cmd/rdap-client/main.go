// Package main provides a CLI client for the rdap-lookup service.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/glimps-re/rdap-lookup/pkg/rdaplookup"
)

// Build information set at build time via ldflags.
var (
	Version = "dev"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	args := os.Args[1:]

	if len(args) == 0 {
		printUsage()
		return nil
	}

	cmd := args[0]

	switch cmd {
	case "help", "-h", "--help":
		printUsage()
		return nil

	case "version", "-v", "--version":
		fmt.Printf("rdap-client version %s\n", Version)
		return nil

	case "domain":
		return runDomain(args[1:])

	case "ip":
		return runIP(args[1:])

	case "asn":
		return runASN(args[1:])

	case "entity":
		return runEntity(args[1:])

	case "batch":
		return runBatch(args[1:])

	case "health":
		return runHealth(args[1:])

	default:
		return fmt.Errorf("unknown command: %s", cmd)
	}
}

func printUsage() {
	fmt.Print(`rdap-client - CLI for rdap-lookup service

Usage:
  rdap-client <command> [options] [arguments]

Commands:
  domain <name>           Lookup domain information
  ip <address>            Lookup IP address information
  asn <number>            Lookup ASN information
  entity <handle>         Lookup entity information (requires --rdap-server)
  batch <file|-|queries>  Batch lookup from file, stdin, or inline
  health                  Check server health (REST mode only)
  version                 Show version information
  help                    Show this help

Mode Selection:
  -S, --standalone        Use standalone mode (direct RDAP, no server needed)
  -s, --server <url>      Server URL for REST mode (default: http://localhost:8080)

Global Options:
  -t, --timeout <dur>     Request timeout (default: 30s)
  -o, --output <format>   Output format: json, table (default: json)
  -q, --quiet             Suppress non-essential output
  -h, --help              Show help for command

Standalone Mode Options (only with --standalone):
  --cache-size <size>     RAM cache size (default: 50MB)
  --cache-ttl <dur>       Cache TTL for responses (default: 24h)
  --negative-ttl <dur>    Cache TTL for not-found (default: 1h)
  --no-cache              Disable caching entirely
  --no-normalize          Disable domain normalization

Examples:
  # REST mode (requires server)
  rdap-client domain example.com
  rdap-client -s http://api.example.com:8080 ip 8.8.8.8

  # Standalone mode (no server required)
  rdap-client --standalone domain example.com
  rdap-client -S ip 8.8.8.8
  rdap-client -S --cache-size 100MB domain google.com
  rdap-client -S batch domain:example.com ip:8.8.8.8 asn:15169

Environment Variables:
  RDAP_SERVER_URL         Default server URL (REST mode)
  RDAP_TIMEOUT            Default timeout
  RDAP_STANDALONE         Enable standalone mode (1/true)
  RDAP_CACHE_SIZE         Default cache size (standalone)
  RDAP_CACHE_TTL          Default cache TTL (standalone)
  RDAP_NEGATIVE_TTL       Default negative TTL (standalone)
`)
}

// Config holds CLI configuration.
type Config struct {
	// REST mode settings
	ServerURL string
	Timeout   time.Duration
	Output    string
	Quiet     bool

	// Standalone mode settings
	Standalone      bool
	CacheSize       int64
	CacheTTL        time.Duration
	NegativeTTL     time.Duration
	NoCache         bool
	NormalizeDomain bool
}

func parseConfig(args []string) (*Config, []string, error) {
	cfg := &Config{
		// REST mode defaults
		ServerURL: getEnvOrDefault("RDAP_SERVER_URL", "http://localhost:8080"),
		Timeout:   parseDurationOrDefault(getEnvOrDefault("RDAP_TIMEOUT", "30s"), 30*time.Second),
		Output:    "json",
		Quiet:     false,

		// Standalone mode defaults
		Standalone:      parseBoolOrDefault(getEnvOrDefault("RDAP_STANDALONE", ""), false),
		CacheSize:       parseSizeOrDefault(getEnvOrDefault("RDAP_CACHE_SIZE", ""), 50*1024*1024),
		CacheTTL:        parseDurationOrDefault(getEnvOrDefault("RDAP_CACHE_TTL", ""), 24*time.Hour),
		NegativeTTL:     parseDurationOrDefault(getEnvOrDefault("RDAP_NEGATIVE_TTL", ""), time.Hour),
		NoCache:         false,
		NormalizeDomain: true,
	}

	var remaining []string
	for i := 0; i < len(args); i++ {
		arg := args[i]

		switch {
		case arg == "-s" || arg == "--server":
			if i+1 >= len(args) {
				return nil, nil, fmt.Errorf("missing value for %s", arg)
			}
			i++
			cfg.ServerURL = args[i]

		case arg == "-t" || arg == "--timeout":
			if i+1 >= len(args) {
				return nil, nil, fmt.Errorf("missing value for %s", arg)
			}
			i++
			d, err := time.ParseDuration(args[i])
			if err != nil {
				return nil, nil, fmt.Errorf("invalid timeout: %w", err)
			}
			cfg.Timeout = d

		case arg == "-o" || arg == "--output":
			if i+1 >= len(args) {
				return nil, nil, fmt.Errorf("missing value for %s", arg)
			}
			i++
			if args[i] != "json" && args[i] != "table" {
				return nil, nil, fmt.Errorf("invalid output format: %s (use 'json' or 'table')", args[i])
			}
			cfg.Output = args[i]

		case arg == "-q" || arg == "--quiet":
			cfg.Quiet = true

		case arg == "-S" || arg == "--standalone":
			cfg.Standalone = true

		case arg == "--cache-size":
			if i+1 >= len(args) {
				return nil, nil, fmt.Errorf("missing value for %s", arg)
			}
			i++
			size, err := parseSize(args[i])
			if err != nil {
				return nil, nil, fmt.Errorf("invalid cache size: %w", err)
			}
			cfg.CacheSize = size

		case arg == "--cache-ttl":
			if i+1 >= len(args) {
				return nil, nil, fmt.Errorf("missing value for %s", arg)
			}
			i++
			d, err := time.ParseDuration(args[i])
			if err != nil {
				return nil, nil, fmt.Errorf("invalid cache TTL: %w", err)
			}
			cfg.CacheTTL = d

		case arg == "--negative-ttl":
			if i+1 >= len(args) {
				return nil, nil, fmt.Errorf("missing value for %s", arg)
			}
			i++
			d, err := time.ParseDuration(args[i])
			if err != nil {
				return nil, nil, fmt.Errorf("invalid negative TTL: %w", err)
			}
			cfg.NegativeTTL = d

		case arg == "--no-cache":
			cfg.NoCache = true

		case arg == "--no-normalize":
			cfg.NormalizeDomain = false

		case arg == "-h" || arg == "--help":
			return nil, nil, nil // Signal to show help

		case strings.HasPrefix(arg, "-"):
			return nil, nil, fmt.Errorf("unknown option: %s", arg)

		default:
			remaining = append(remaining, arg)
		}
	}

	return cfg, remaining, nil
}

func getEnvOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

func parseDurationOrDefault(s string, defaultValue time.Duration) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return defaultValue
	}
	return d
}

func parseBoolOrDefault(s string, defaultValue bool) bool {
	switch strings.ToLower(s) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return defaultValue
	}
}

// parseSize parses a size string like "50MB", "1GB" into bytes.
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return 0, errors.New("empty size string")
	}

	// Check longer suffixes first to avoid partial matches
	suffixes := []struct {
		suffix string
		mult   int64
	}{
		{"GB", 1024 * 1024 * 1024},
		{"MB", 1024 * 1024},
		{"KB", 1024},
		{"G", 1024 * 1024 * 1024},
		{"M", 1024 * 1024},
		{"K", 1024},
		{"B", 1},
	}

	for _, s2 := range suffixes {
		if numStr, found := strings.CutSuffix(s, s2.suffix); found {
			num, err := strconv.ParseInt(numStr, 10, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid size: %s", s)
			}
			return num * s2.mult, nil
		}
	}

	// Assume bytes if no suffix
	return strconv.ParseInt(s, 10, 64)
}

func parseSizeOrDefault(s string, defaultValue int64) int64 {
	v, err := parseSize(s)
	if err != nil {
		return defaultValue
	}
	return v
}

// createClient creates an RDAPClient based on configuration.
// Returns a StandaloneClient if --standalone is set, otherwise a REST Client.
func createClient(cfg *Config) (rdaplookup.RDAPClient, error) {
	if cfg.Standalone {
		opts := []rdaplookup.StandaloneOption{
			rdaplookup.WithStandaloneTimeout(cfg.Timeout),
			rdaplookup.WithStandaloneDomainNormalization(cfg.NormalizeDomain),
		}

		if cfg.NoCache {
			opts = append(opts, rdaplookup.WithoutCache())
		} else {
			opts = append(opts,
				rdaplookup.WithCacheSize(cfg.CacheSize),
				rdaplookup.WithCacheTTL(cfg.CacheTTL),
				rdaplookup.WithNegativeTTL(cfg.NegativeTTL),
			)
		}

		return rdaplookup.NewStandaloneClient(opts...)
	}

	return rdaplookup.NewClient(cfg.ServerURL, rdaplookup.WithTimeout(cfg.Timeout))
}

func runDomain(args []string) error {
	cfg, remaining, err := parseConfig(args)
	if err != nil {
		return err
	}
	if cfg == nil {
		fmt.Print(`rdap-client domain - Lookup domain information

Usage:
  rdap-client domain [options] <domain-name>

Options:
  -S, --standalone        Use standalone mode (no server required)
  -s, --server <url>      Server URL (default: http://localhost:8080)
  -t, --timeout <dur>     Request timeout (default: 30s)
  -o, --output <format>   Output format: json, table (default: json)
  -q, --quiet             Suppress non-essential output

Standalone Options:
  --cache-size <size>     RAM cache size (default: 50MB)
  --cache-ttl <dur>       Cache TTL (default: 24h)
  --no-cache              Disable caching
  --no-normalize          Disable domain normalization

Examples:
  rdap-client domain example.com
  rdap-client domain example.com -o table
  rdap-client -S domain example.com
  rdap-client --standalone --cache-size 100MB domain google.com
`)
		return nil
	}

	if len(remaining) == 0 {
		return errors.New("missing domain name")
	}
	domain := remaining[0]

	client, err := createClient(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	resp, err := client.LookupDomain(ctx, domain)
	if err != nil {
		return formatError(err)
	}

	return outputResult(resp, cfg.Output, formatDomainTable)
}

func runIP(args []string) error {
	cfg, remaining, err := parseConfig(args)
	if err != nil {
		return err
	}
	if cfg == nil {
		fmt.Print(`rdap-client ip - Lookup IP address information

Usage:
  rdap-client ip [options] <ip-address>

Options:
  -S, --standalone        Use standalone mode (no server required)
  -s, --server <url>      Server URL (default: http://localhost:8080)
  -t, --timeout <dur>     Request timeout (default: 30s)
  -o, --output <format>   Output format: json, table (default: json)
  -q, --quiet             Suppress non-essential output

Standalone Options:
  --cache-size <size>     RAM cache size (default: 50MB)
  --cache-ttl <dur>       Cache TTL (default: 24h)
  --no-cache              Disable caching

Examples:
  rdap-client ip 8.8.8.8
  rdap-client ip 2001:4860:4860::8888
  rdap-client -S ip 8.8.8.8
`)
		return nil
	}

	if len(remaining) == 0 {
		return errors.New("missing IP address")
	}
	addr := remaining[0]

	client, err := createClient(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	resp, err := client.LookupIP(ctx, addr)
	if err != nil {
		return formatError(err)
	}

	return outputResult(resp, cfg.Output, formatIPTable)
}

func runASN(args []string) error {
	cfg, remaining, err := parseConfig(args)
	if err != nil {
		return err
	}
	if cfg == nil {
		fmt.Print(`rdap-client asn - Lookup ASN information

Usage:
  rdap-client asn [options] <asn-number>

Options:
  -S, --standalone        Use standalone mode (no server required)
  -s, --server <url>      Server URL (default: http://localhost:8080)
  -t, --timeout <dur>     Request timeout (default: 30s)
  -o, --output <format>   Output format: json, table (default: json)
  -q, --quiet             Suppress non-essential output

Standalone Options:
  --cache-size <size>     RAM cache size (default: 50MB)
  --cache-ttl <dur>       Cache TTL (default: 24h)
  --no-cache              Disable caching

Examples:
  rdap-client asn 15169
  rdap-client asn AS15169
  rdap-client -S asn 15169
`)
		return nil
	}

	if len(remaining) == 0 {
		return errors.New("missing ASN number")
	}
	asn := remaining[0]

	client, err := createClient(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	resp, err := client.LookupASN(ctx, asn)
	if err != nil {
		return formatError(err)
	}

	return outputResult(resp, cfg.Output, formatASNTable)
}

func runEntity(args []string) error {
	cfg, remaining, err := parseConfig(args)
	if err != nil {
		return err
	}
	if cfg == nil {
		fmt.Print(`rdap-client entity - Lookup entity information

Usage:
  rdap-client entity [options] <handle>

Options:
  -S, --standalone        Use standalone mode (no server required)
  -s, --server <url>      Server URL (default: http://localhost:8080)
  -t, --timeout <dur>     Request timeout (default: 30s)
  -o, --output <format>   Output format: json, table (default: json)
  -q, --quiet             Suppress non-essential output
  --rdap-server <url>     RDAP server to query for entity (required)

Standalone Options:
  --cache-size <size>     RAM cache size (default: 50MB)
  --cache-ttl <dur>       Cache TTL (default: 24h)
  --no-cache              Disable caching

Note: Entity lookups require an RDAP server URL because entities are not
bootstrappable via IANA. Use --rdap-server to specify the RDAP server.

Examples:
  rdap-client entity ABC-123 --rdap-server https://rdap.arin.net
  rdap-client -S entity XYZ-456 --rdap-server https://rdap.ripe.net
`)
		return nil
	}

	// Check for --rdap-server in remaining args
	var handle, rdapServer string
	for i := 0; i < len(remaining); i++ {
		if remaining[i] == "--rdap-server" && i+1 < len(remaining) {
			rdapServer = remaining[i+1]
			i++
		} else if !strings.HasPrefix(remaining[i], "-") {
			handle = remaining[i]
		}
	}

	if handle == "" {
		return errors.New("missing entity handle")
	}
	if rdapServer == "" {
		return errors.New("missing --rdap-server (required for entity lookups)")
	}

	client, err := createClient(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	resp, err := client.LookupEntity(ctx, handle, rdapServer)
	if err != nil {
		return formatError(err)
	}

	return outputResult(resp, cfg.Output, formatEntityTable)
}

func runBatch(args []string) error {
	cfg, remaining, err := parseConfig(args)
	if err != nil {
		return err
	}
	if cfg == nil {
		fmt.Print(`rdap-client batch - Batch lookup from file or stdin

Usage:
  rdap-client batch [options] <file|-|queries...>

Options:
  -S, --standalone        Use standalone mode (no server required)
  -s, --server <url>      Server URL (default: http://localhost:8080)
  -t, --timeout <dur>     Request timeout (default: 30s)
  -o, --output <format>   Output format: json, table (default: json)
  -q, --quiet             Suppress non-essential output

Standalone Options:
  --cache-size <size>     RAM cache size (default: 50MB)
  --cache-ttl <dur>       Cache TTL (default: 24h)
  --no-cache              Disable caching

Input Format:
  Each line should be in format: type:value
  Supported types: domain, ip, asn

Examples:
  rdap-client batch queries.txt
  echo -e "domain:example.com\nip:8.8.8.8" | rdap-client batch -
  rdap-client -S batch domain:example.com ip:8.8.8.8 asn:15169
`)
		return nil
	}

	if len(remaining) == 0 {
		return errors.New("missing input (file, '-' for stdin, or inline queries)")
	}

	// Collect queries
	var queries []rdaplookup.BatchQuery

	if remaining[0] == "-" {
		// Read from stdin
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			q, err := parseBatchQuery(line)
			if err != nil {
				return fmt.Errorf("invalid query %q: %w", line, err)
			}
			queries = append(queries, q)
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("error reading stdin: %w", err)
		}
	} else if _, err := os.Stat(remaining[0]); err == nil {
		// Read from file
		file, err := os.Open(remaining[0])
		if err != nil {
			return fmt.Errorf("failed to open file: %w", err)
		}
		defer func() { _ = file.Close() }()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			q, err := parseBatchQuery(line)
			if err != nil {
				return fmt.Errorf("invalid query %q: %w", line, err)
			}
			queries = append(queries, q)
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("error reading file: %w", err)
		}
	} else {
		// Parse inline queries
		for _, arg := range remaining {
			q, err := parseBatchQuery(arg)
			if err != nil {
				return fmt.Errorf("invalid query %q: %w", arg, err)
			}
			queries = append(queries, q)
		}
	}

	if len(queries) == 0 {
		return errors.New("no queries provided")
	}

	client, err := createClient(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	resp, err := client.BatchLookup(ctx, &rdaplookup.BatchRequest{Queries: queries})
	if err != nil {
		return formatError(err)
	}

	return outputResult(resp, cfg.Output, formatBatchTable)
}

func parseBatchQuery(s string) (rdaplookup.BatchQuery, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return rdaplookup.BatchQuery{}, errors.New("expected format 'type:value'")
	}

	qType := strings.ToLower(strings.TrimSpace(parts[0]))
	value := strings.TrimSpace(parts[1])

	switch qType {
	case "domain", "ip", "asn":
		return rdaplookup.BatchQuery{Type: qType, Value: value}, nil
	default:
		return rdaplookup.BatchQuery{}, fmt.Errorf("unsupported query type: %s", qType)
	}
}

func runHealth(args []string) error {
	cfg, _, err := parseConfig(args)
	if err != nil {
		return err
	}
	if cfg == nil {
		fmt.Print(`rdap-client health - Check server health

Usage:
  rdap-client health [options]

Options:
  -s, --server <url>      Server URL (default: http://localhost:8080)
  -t, --timeout <dur>     Request timeout (default: 30s)

Note: This command is only available in REST mode (not with --standalone).

Examples:
  rdap-client health
  rdap-client health -s http://api.example.com:8080
`)
		return nil
	}

	if cfg.Standalone {
		return errors.New("health command is only available in REST mode (remove --standalone)")
	}

	client, err := rdaplookup.NewClient(cfg.ServerURL, rdaplookup.WithTimeout(cfg.Timeout))
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	if err := client.Health(ctx); err != nil {
		return fmt.Errorf("server unhealthy: %w", err)
	}

	if err := client.Ready(ctx); err != nil {
		return fmt.Errorf("server not ready: %w", err)
	}

	meta, err := client.Meta(ctx)
	if err != nil {
		fmt.Println("Server is healthy and ready")
		return nil
	}

	fmt.Printf("Server is healthy and ready\n")
	fmt.Printf("  Component: %s\n", meta.Component)
	fmt.Printf("  Version:   %s\n", meta.Version)
	if meta.Hostname != "" {
		fmt.Printf("  Hostname:  %s\n", meta.Hostname)
	}

	return nil
}

func formatError(err error) error {
	if rdaplookup.IsNotFoundError(err) {
		return errors.New("not found")
	}
	if rdaplookup.IsRateLimitedError(err) {
		return errors.New("rate limited - try again later")
	}
	return err
}

func outputResult(data any, format string, tableFunc func(any)) error {
	if format == "table" {
		tableFunc(data)
		return nil
	}

	// JSON output
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}

func formatDomainTable(data any) {
	d, ok := data.(*rdaplookup.DomainResponse)
	if !ok {
		return
	}

	fmt.Printf("Domain: %s\n", d.Name)
	fmt.Printf("Status: %s\n", strings.Join(d.Status, ", "))
	if d.CreatedDate != "" {
		fmt.Printf("Created: %s\n", d.CreatedDate)
	}
	if d.ExpirationDate != "" {
		fmt.Printf("Expires: %s\n", d.ExpirationDate)
	}
	if d.Registrar != nil && d.Registrar.Name != "" {
		fmt.Printf("Registrar: %s\n", d.Registrar.Name)
	}
	if d.Country != "" {
		fmt.Printf("Country: %s\n", d.Country)
	}
	if len(d.Nameservers) > 0 {
		fmt.Print("Nameservers:\n")
		for _, ns := range d.Nameservers {
			fmt.Printf("  - %s\n", ns.Name)
		}
	}
	if d.DNSSEC != nil {
		fmt.Printf("DNSSEC: signed=%v delegation_signed=%v\n", d.DNSSEC.Signed, d.DNSSEC.DelegationSigned)
	} else {
		fmt.Printf("DNSSEC: none\n")
	}
}

func formatIPTable(data any) {
	d, ok := data.(*rdaplookup.IPResponse)
	if !ok {
		return
	}

	if len(d.CIDR) > 0 {
		fmt.Printf("Network: %s\n", strings.Join(d.CIDR, ", "))
	} else {
		fmt.Printf("Range: %s - %s\n", d.StartAddress, d.EndAddress)
	}
	if d.Name != "" {
		fmt.Printf("Name: %s\n", d.Name)
	}
	if d.Handle != "" {
		fmt.Printf("Handle: %s\n", d.Handle)
	}
	if d.Country != "" {
		fmt.Printf("Country: %s\n", d.Country)
	}
	// Print contacts
	if d.Registrant != nil && d.Registrant.Name != "" {
		fmt.Printf("Registrant: %s\n", d.Registrant.Name)
	}
	if d.AbuseContact != nil && d.AbuseContact.Email != "" {
		fmt.Printf("Abuse Contact: %s\n", d.AbuseContact.Email)
	}
}

func formatASNTable(data any) {
	d, ok := data.(*rdaplookup.ASNResponse)
	if !ok {
		return
	}

	fmt.Printf("ASN: %d\n", d.StartAutnum)
	if d.Name != "" {
		fmt.Printf("Name: %s\n", d.Name)
	}
	if d.Handle != "" {
		fmt.Printf("Handle: %s\n", d.Handle)
	}
	if d.Country != "" {
		fmt.Printf("Country: %s\n", d.Country)
	}
	if len(d.Entities) > 0 {
		fmt.Print("Entities:\n")
		for _, e := range d.Entities {
			roles := strings.Join(e.Roles, ", ")
			fmt.Printf("  - %s (%s)\n", e.Name, roles)
		}
	}
}

func formatEntityTable(data any) {
	d, ok := data.(*rdaplookup.EntityResponse)
	if !ok {
		return
	}

	fmt.Printf("Handle: %s\n", d.Handle)
	if d.Name != "" {
		fmt.Printf("Name: %s\n", d.Name)
	}
	if d.Organization != "" {
		fmt.Printf("Organization: %s\n", d.Organization)
	}
	if d.Email != "" {
		fmt.Printf("Email: %s\n", d.Email)
	}
	if d.Phone != "" {
		fmt.Printf("Phone: %s\n", d.Phone)
	}
	if d.Country != "" {
		fmt.Printf("Country: %s\n", d.Country)
	}
	if len(d.Roles) > 0 {
		fmt.Printf("Roles: %s\n", strings.Join(d.Roles, ", "))
	}
}

func formatBatchTable(data any) {
	d, ok := data.(*rdaplookup.BatchResponse)
	if !ok {
		return
	}

	for _, r := range d.Results {
		if r.Error != "" {
			fmt.Printf("[%s] %s: ERROR - %s\n", r.Type, r.Value, r.Error)
		} else {
			cached := ""
			if r.Cached {
				cached = " (cached)"
			}
			fmt.Printf("[%s] %s: OK%s\n", r.Type, r.Value, cached)
		}
	}

	if d.Stats != nil {
		fmt.Printf("\nStats: %d total, %d success, %d errors, %d cache hits, %dms\n",
			d.Stats.Total, d.Stats.Success, d.Stats.Errors, d.Stats.CacheHits, d.Stats.DurationMs)
	}
}
