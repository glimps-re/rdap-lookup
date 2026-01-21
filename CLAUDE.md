# Claude Code Conventions - rdap-lookup

This document outlines the coding standards, architecture, and implementation requirements for the rdap-lookup project.

## Important

Do not commit CLAUDE.md file, CLAUDE.md MUST NOT be added to git.

**All temporary work files must be stored in the `./tmp/` directory.**

## Project Overview

**rdap-lookup** is a high-performance domain name lookup REST API using the RDAP protocol.

### Key Features
- RDAP protocol support for all query types (domain, nameserver, entity, IP, ASN)
- All TLDs supported via IANA bootstrap
- Two-tier caching: RAM (L1) -> Redis (L2) -> RDAP (upstream)
- Simplified response schema with country information
- Batch and single query support
- Horizontal scaling with Redis backend
- Prometheus metrics and structured logging (slog)

### Performance Targets
- **10,000 requests/second** throughput
- Sub-millisecond cache hits
- Graceful degradation under load

## Architecture

### High-Level Design
```
┌─────────────────────────────────────────────────────────────────┐
│                         REST API (Echo)                         │
│  /domain/{name}  /ip/{addr}  /asn/{number}  /entity/{handle}   │
│  /batch          /health     /ready         /metrics            │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Cache Layer                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │
│  │  RAM Cache  │───▶│ Redis Cache │───▶│  RDAP Client        │ │
│  │  (L1, LRU)  │    │  (L2, opt)  │    │  (upstream servers) │ │
│  │  100MB def  │    │  shared     │    │  10s timeout        │ │
│  └─────────────┘    └─────────────┘    └─────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                     IANA Bootstrap                              │
│  - Domain TLD -> RDAP server mapping                            │
│  - IP range -> RIR RDAP server mapping                          │
│  - ASN range -> RIR RDAP server mapping                         │
│  - Auto-refresh every 24h (configurable)                        │
└─────────────────────────────────────────────────────────────────┘
```

### Project Structure
```
rdap-lookup/
├── cmd/
│   └── rdap-lookup/
│       └── main.go              # Entry point, minimal
├── internal/
│   ├── api/                     # HTTP handlers and routing
│   │   ├── handlers.go          # Request handlers
│   │   ├── middleware.go        # Logging, metrics middleware
│   │   ├── routes.go            # Echo route setup
│   │   └── response.go          # Response types and helpers
│   ├── bootstrap/               # IANA bootstrap management
│   │   ├── bootstrap.go         # Bootstrap data structures
│   │   ├── loader.go            # IANA file fetching/parsing
│   │   └── resolver.go          # TLD/IP/ASN -> RDAP URL resolution
│   ├── cache/                   # Caching layer
│   │   ├── cache.go             # Cache interface
│   │   ├── memory.go            # LRU RAM cache implementation
│   │   ├── redis.go             # Redis cache implementation
│   │   └── tiered.go            # L1 (RAM) -> L2 (Redis) orchestration
│   ├── config/                  # Configuration management
│   │   └── config.go            # Config struct, env/file loading
│   ├── metrics/                 # Prometheus metrics
│   │   └── metrics.go           # Metric definitions and registration
│   ├── rdap/                    # RDAP client
│   │   ├── client.go            # HTTP client for RDAP queries
│   │   ├── types.go             # Raw RDAP response types
│   │   └── parser.go            # RDAP response parsing
│   └── schema/                  # Simplified output schema
│       ├── domain.go            # Domain response schema
│       ├── ip.go                # IP response schema
│       ├── asn.go               # ASN response schema
│       ├── entity.go            # Entity response schema
│       └── common.go            # Shared types (registrar, contact, etc.)
├── pkg/                         # Public library (if needed later)
├── bin/                         # Compiled binaries (gitignored)
├── tmp/                         # Temporary files (gitignored)
├── testdata/                    # Test fixtures
└── go.mod
```

## Configuration

### Environment Variables
All configuration via environment variables with sensible defaults:

```bash
# Server
RDAP_LISTEN_ADDR=":8080"           # Listen address
RDAP_READ_TIMEOUT="30s"            # HTTP read timeout
RDAP_WRITE_TIMEOUT="30s"           # HTTP write timeout
RDAP_SHUTDOWN_TIMEOUT="30s"        # Graceful shutdown timeout

# Cache - General
RDAP_CACHE_TTL="24h"               # Default cache TTL
RDAP_CACHE_NEGATIVE_TTL="1h"       # TTL for "not found" responses

# Cache - RAM (L1)
RDAP_CACHE_RAM_ENABLED="true"      # Enable RAM cache
RDAP_CACHE_RAM_MAX_SIZE="100MB"    # Maximum RAM cache size
RDAP_CACHE_RAM_EVICTION="lru"      # Eviction policy

# Cache - Redis (L2)
RDAP_CACHE_REDIS_ENABLED="false"   # Enable Redis cache
RDAP_CACHE_REDIS_ADDR=""           # Redis address (host:port)
RDAP_CACHE_REDIS_PASSWORD=""       # Redis password
RDAP_CACHE_REDIS_DB="0"            # Redis database number

# RDAP Client
RDAP_CLIENT_TIMEOUT="10s"          # Upstream RDAP request timeout
RDAP_CLIENT_MAX_RETRIES="2"        # Max retries for failed requests

# Bootstrap
RDAP_BOOTSTRAP_REFRESH="24h"       # IANA bootstrap refresh interval

# Logging
RDAP_LOG_LEVEL="info"              # Log level (debug, info, warn, error)
RDAP_LOG_FORMAT="json"             # Log format (json, text)
```

### Configuration Precedence
1. Environment variables (highest priority)
2. Config file (if specified)
3. Default values

## API Endpoints

### Query Endpoints
```
GET  /domain/{name}              # Domain lookup
GET  /ip/{address}               # IP lookup (v4 or v6)
GET  /asn/{number}               # ASN lookup
GET  /entity/{handle}            # Entity lookup
GET  /nameserver/{name}          # Nameserver lookup
POST /batch                      # Batch lookup (JSON body)
```

### Operational Endpoints
```
GET  /healthz                    # Liveness probe
GET  /ready                      # Readiness probe
GET  /metrics                    # Prometheus metrics
```

### Batch Request Format
```json
{
  "queries": [
    {"type": "domain", "value": "example.com"},
    {"type": "ip", "value": "8.8.8.8"},
    {"type": "asn", "value": "15169"}
  ]
}
```

### Batch Response Format
```json
{
  "results": [
    {"type": "domain", "value": "example.com", "data": {...}, "cached": true},
    {"type": "ip", "value": "8.8.8.8", "data": {...}, "cached": false},
    {"type": "asn", "value": "15169", "error": "not found"}
  ],
  "stats": {
    "total": 3,
    "success": 2,
    "errors": 1,
    "cache_hits": 1,
    "duration_ms": 245
  }
}
```

## Simplified Response Schema

### Domain Response
```json
{
  "name": "example.com",
  "status": ["active", "clientTransferProhibited"],
  "registration": {
    "created": "1995-08-14T00:00:00Z",
    "updated": "2024-08-14T00:00:00Z",
    "expires": "2025-08-13T00:00:00Z"
  },
  "registrar": {
    "name": "Example Registrar, Inc.",
    "url": "https://www.example-registrar.com",
    "abuse_email": "abuse@example-registrar.com",
    "abuse_phone": "+1.5555551234",
    "country": "US"
  },
  "nameservers": ["ns1.example.com", "ns2.example.com"],
  "dnssec": {
    "enabled": true,
    "delegation_signed": true
  },
  "contacts": {
    "registrant": {
      "name": "REDACTED FOR PRIVACY",
      "organization": "Example Inc.",
      "country": "US"
    },
    "admin": {...},
    "tech": {...}
  },
  "raw_rdap_url": "https://rdap.verisign.com/com/v1/domain/example.com"
}
```

### IP Response
```json
{
  "address": "8.8.8.8",
  "range": "8.8.8.0/24",
  "name": "LVLT-GOGL-8-8-8",
  "type": "ALLOCATION",
  "country": "US",
  "registration": {
    "created": "2014-03-14T00:00:00Z",
    "updated": "2014-03-14T00:00:00Z"
  },
  "entities": [
    {
      "handle": "GOGL",
      "name": "Google LLC",
      "roles": ["registrant"],
      "country": "US"
    }
  ],
  "raw_rdap_url": "https://rdap.arin.net/registry/ip/8.8.8.8"
}
```

### ASN Response
```json
{
  "asn": 15169,
  "name": "GOOGLE",
  "type": "DIRECT ALLOCATION",
  "country": "US",
  "registration": {
    "created": "2000-03-30T00:00:00Z",
    "updated": "2012-02-24T00:00:00Z"
  },
  "entities": [
    {
      "handle": "GOGL",
      "name": "Google LLC",
      "roles": ["registrant"],
      "country": "US"
    }
  ],
  "raw_rdap_url": "https://rdap.arin.net/registry/autnum/15169"
}
```

## Cache Strategy

### Cache Key Format
```
rdap:{type}:{normalized_value}

Examples:
- rdap:domain:example.com
- rdap:ip:8.8.8.8
- rdap:asn:15169
- rdap:entity:abc123-arin
```

### Cache Flow (L1 -> L2 -> Upstream)
```go
func (c *TieredCache) Get(ctx context.Context, key string) (*CacheEntry, error) {
    // 1. Check RAM cache (L1)
    if entry, found := c.ram.Get(key); found {
        metrics.CacheHits.WithLabelValues("ram").Inc()
        return entry, nil
    }

    // 2. Check Redis cache (L2) if enabled
    if c.redis != nil {
        if entry, err := c.redis.Get(ctx, key); err == nil && entry != nil {
            metrics.CacheHits.WithLabelValues("redis").Inc()
            // Promote to L1
            c.ram.Set(key, entry)
            return entry, nil
        }
    }

    metrics.CacheMisses.Inc()
    return nil, ErrCacheMiss
}
```

### TTL Strategy
- **Positive responses**: 24h default (configurable via `RDAP_CACHE_TTL`)
- **Negative responses** (not found): 1h default (configurable via `RDAP_CACHE_NEGATIVE_TTL`)
- **Error responses**: Not cached

## Prometheus Metrics

### Required Metrics
```go
// HTTP metrics
http_requests_total{method, endpoint, status_code}
http_request_duration_seconds{method, endpoint}
http_requests_in_flight

// Cache metrics
rdap_cache_hits_total{cache_layer}           // "ram" or "redis"
rdap_cache_misses_total
rdap_cache_size_bytes{cache_layer}
rdap_cache_entries{cache_layer}
rdap_cache_evictions_total{cache_layer}

// RDAP client metrics
rdap_upstream_requests_total{server, status}
rdap_upstream_request_duration_seconds{server}
rdap_upstream_errors_total{server, error_type}

// Bootstrap metrics
rdap_bootstrap_last_refresh_timestamp
rdap_bootstrap_tlds_loaded
rdap_bootstrap_refresh_errors_total

// Business metrics
rdap_lookups_total{type}                     // domain, ip, asn, entity
rdap_batch_requests_total
rdap_batch_size_histogram
```

## Dependencies

### Required (MIT/BSD/Apache licensed)
```go
// Web framework
github.com/labstack/echo/v4              // MIT - HTTP framework

// Cache
github.com/hashicorp/golang-lru/v2       // MPL-2.0 - LRU cache
github.com/redis/go-redis/v9             // BSD-2 - Redis client

// Observability
github.com/prometheus/client_golang      // Apache-2.0 - Prometheus

// Utilities
golang.org/x/sync/errgroup               // BSD-3 - Concurrency
golang.org/x/time/rate                   // BSD-3 - Rate limiting (future)
```

### Standard Library Only
- `log/slog` - Structured logging
- `net/http` - HTTP client for RDAP
- `encoding/json` - JSON parsing
- `context` - Request context
- `sync` - Concurrency primitives

## Implementation Milestones

### Milestone 1: Project Foundation
- [ ] Project structure and go.mod
- [ ] Configuration management (env vars)
- [ ] Structured logging setup (slog)
- [ ] Basic Echo server with health endpoints
- [ ] Prometheus metrics setup

### Milestone 2: IANA Bootstrap
- [ ] Bootstrap data structures
- [ ] IANA JSON file fetcher
- [ ] TLD -> RDAP URL resolver
- [ ] IP range -> RIR resolver
- [ ] ASN range -> RIR resolver
- [ ] Background refresh mechanism

### Milestone 3: RDAP Client
- [ ] HTTP client with timeouts
- [ ] Domain query implementation
- [ ] IP query implementation
- [ ] ASN query implementation
- [ ] Entity query implementation
- [ ] Nameserver query implementation
- [ ] Error handling and retries

### Milestone 4: Response Schema
- [ ] Raw RDAP response types
- [ ] Simplified domain schema + transformer
- [ ] Simplified IP schema + transformer
- [ ] Simplified ASN schema + transformer
- [ ] Simplified entity schema + transformer
- [ ] Country extraction logic

### Milestone 5: RAM Cache (L1)
- [ ] LRU cache implementation
- [ ] Size-bounded memory management
- [ ] TTL support with expiration
- [ ] Negative caching
- [ ] Cache metrics

### Milestone 6: Redis Cache (L2)
- [ ] Redis client setup
- [ ] Cache interface implementation
- [ ] TTL support
- [ ] Connection health checks
- [ ] Fallback when Redis unavailable

### Milestone 7: Tiered Cache
- [ ] L1 -> L2 -> upstream orchestration
- [ ] L1 promotion on L2 hits
- [ ] Concurrent cache population (singleflight)
- [ ] Cache invalidation support

### Milestone 8: API Handlers
- [ ] Single lookup endpoints (domain, ip, asn, entity)
- [ ] Batch lookup endpoint
- [ ] Error response formatting
- [ ] Request validation

### Milestone 9: Production Readiness
- [ ] Graceful shutdown
- [ ] Request timeouts
- [ ] Comprehensive tests
- [ ] Benchmarks
- [ ] Documentation

## Security Considerations

### Input Validation
- Validate domain names (IDN support, length limits)
- Validate IP addresses (v4/v6 format)
- Validate ASN numbers (range: 1-4294967295)
- Sanitize entity handles
- Limit batch size (max 100 queries)

### Rate Limiting (Future)
- Per-IP rate limiting when needed
- Configurable limits
- 429 responses with Retry-After header

### RDAP Server Trust
- Only connect to servers from IANA bootstrap
- Verify HTTPS certificates
- Timeout all upstream requests
- Don't follow arbitrary redirects

## Testing Requirements

### Unit Tests
- Bootstrap parsing and resolution
- Cache operations (RAM and Redis)
- Schema transformations
- Input validation

### Integration Tests
- Full request/response cycle
- Cache tier interactions
- Bootstrap refresh
- Graceful shutdown

### Benchmarks
```go
func BenchmarkDomainLookup_CacheHit(b *testing.B)
func BenchmarkDomainLookup_CacheMiss(b *testing.B)
func BenchmarkBatchLookup_10(b *testing.B)
func BenchmarkBatchLookup_100(b *testing.B)
func BenchmarkCacheLRU_Set(b *testing.B)
func BenchmarkCacheLRU_Get(b *testing.B)
```

### Load Testing
- Use `hey` or `vegeta` for load testing
- Target: 10k req/s with cache warm
- Measure p50, p95, p99 latencies

## Error Handling

### Error Response Format
```json
{
  "error": {
    "code": "NOT_FOUND",
    "message": "Domain not found in RDAP",
    "details": {
      "query": "nonexistent.invalid",
      "upstream_status": 404
    }
  }
}
```

### Error Codes
- `INVALID_REQUEST` - Malformed input
- `NOT_FOUND` - RDAP returned 404
- `UPSTREAM_ERROR` - RDAP server error
- `UPSTREAM_TIMEOUT` - RDAP request timed out
- `RATE_LIMITED` - Upstream rate limit hit
- `INTERNAL_ERROR` - Server error

## Build and Run

### Development
```bash
# Run with hot reload
go run ./cmd/rdap-lookup

# Run tests
go test -v -race ./...

# Run benchmarks
go test -bench=. -benchmem ./...

# Lint
golangci-lint run
```

### Production Build
```bash
# Build binary
go build -ldflags="-s -w -X main.Version=$(git describe --tags)" \
    -o bin/rdap-lookup ./cmd/rdap-lookup

# Docker build
docker build -t rdap-lookup:latest .
```

### Example Requests
```bash
# Domain lookup
curl http://localhost:8080/domain/example.com

# IP lookup
curl http://localhost:8080/ip/8.8.8.8

# ASN lookup
curl http://localhost:8080/asn/15169

# Batch lookup
curl -X POST http://localhost:8080/batch \
  -H "Content-Type: application/json" \
  -d '{"queries":[{"type":"domain","value":"google.com"},{"type":"ip","value":"1.1.1.1"}]}'

# Health check
curl http://localhost:8080/healthz

# Metrics
curl http://localhost:8080/metrics
```
