# rdap-lookup

High-performance RDAP (Registration Data Access Protocol) lookup service with two-tier caching.

## Features

- Full RDAP support: domain, IP, ASN, entity queries
- Two-tier caching: L1 (RAM/LRU) + L2 (Redis, optional)
- IANA bootstrap for automatic RDAP server discovery
- Simplified JSON responses with country extraction
- Batch query support (up to 100 queries)
- Prometheus metrics and structured logging

## Quick Start

### Build

```bash
go build -o bin/rdap-lookup ./cmd/rdap-lookup
go build -o bin/rdap-client ./cmd/rdap-client
```

### Run Server

```bash
./bin/rdap-lookup
```

### Query Examples

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
```

### CLI Usage

```bash
./bin/rdap-client domain example.com
./bin/rdap-client ip 8.8.8.8 -o table
./bin/rdap-client asn 15169 -o json
```

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `RDAP_LISTEN_ADDR` | `:8080` | Server listen address |
| `RDAP_CACHE_TTL` | `24h` | Cache TTL for positive responses |
| `RDAP_CACHE_NEGATIVE_TTL` | `1h` | Cache TTL for not-found responses |
| `RDAP_CACHE_RAM_MAX_SIZE` | `100MB` | L1 cache size limit |
| `RDAP_CACHE_REDIS_ENABLED` | `false` | Enable L2 Redis cache |
| `RDAP_CACHE_REDIS_ADDR` | `localhost:6379` | Redis address |
| `RDAP_CLIENT_TIMEOUT` | `10s` | Upstream RDAP timeout |
| `RDAP_BOOTSTRAP_REFRESH` | `24h` | IANA bootstrap refresh interval |
| `RDAP_LOG_LEVEL` | `info` | Log level (debug, info, warn, error) |
| `RDAP_LOG_FORMAT` | `json` | Log format (json, text) |

## API Endpoints

### Lookup Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/domain/{name}` | Domain lookup |
| GET | `/ip/{address}` | IP address lookup (IPv4 or IPv6) |
| GET | `/asn/{number}` | ASN lookup |
| GET | `/entity/{handle}?server={url}` | Entity lookup (requires server URL) |
| POST | `/batch` | Batch lookup (max 100 queries) |

### Operational Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/healthz` | Liveness probe |
| GET | `/ready` | Readiness probe |
| GET | `/metrics` | Prometheus metrics |
| GET | `/meta` | Service metadata |

## Response Headers

- `X-Cache: HIT` - Response served from cache
- `X-Cache: MISS` - Response fetched from upstream RDAP server

## Client Library

Go client library available at `pkg/rdaplookup`:

```go
import "github.com/glimps-re/rdap-lookup/pkg/rdaplookup"

client, err := rdaplookup.NewClient("http://localhost:8080")
if err != nil {
    log.Fatal(err)
}

// Domain lookup
domain, err := client.LookupDomain(ctx, "example.com")

// IP lookup
ip, err := client.LookupIP(ctx, "8.8.8.8")

// ASN lookup
asn, err := client.LookupASN(ctx, 15169)

// Batch lookup
results, err := client.BatchLookup(ctx, []rdaplookup.Query{
    {Type: "domain", Value: "example.com"},
    {Type: "ip", Value: "1.1.1.1"},
})
```

## Architecture

```
+--------------------------------------------------+
|                 REST API (Echo)                  |
|  /domain  /ip  /asn  /entity  /batch  /metrics  |
+---------------------------+----------------------+
                            |
+---------------------------v----------------------+
|                  Tiered Cache                    |
|  L1 (RAM/LRU) --> L2 (Redis) --> RDAP Upstream  |
+---------------------------+----------------------+
                            |
+---------------------------v----------------------+
|              IANA Bootstrap Resolver             |
|  TLD -> RDAP URL | IP -> RIR | ASN -> RIR       |
+--------------------------------------------------+
```

## Development

### Run Tests

```bash
go test -v -race ./...
```

### Run Linter

```bash
golangci-lint run
```

### Build with Version Info

```bash
VERSION=$(git describe --tags --always)
go build -ldflags="-X main.Version=$VERSION" -o bin/rdap-lookup ./cmd/rdap-lookup
```

## License

MIT

### Third-Party Licenses

This project uses the following third-party dependencies:

| Package | License | Notes |
|---------|---------|-------|
| `github.com/labstack/echo/v4` | MIT | HTTP framework |
| `github.com/prometheus/client_golang` | Apache-2.0 | Prometheus metrics |
| `github.com/redis/go-redis/v9` | BSD-2-Clause | Redis client |
| `github.com/hashicorp/golang-lru/v2` | MPL-2.0 | LRU cache implementation |
| `golang.org/x/time/rate` | BSD-3-Clause | Rate limiting |
| `golang.org/x/sync/singleflight` | BSD-3-Clause | Request coalescing |

**Note on MPL-2.0**: The `golang-lru` library uses MPL-2.0, which is a file-level copyleft license. This project uses the library without modification, satisfying the license requirements. MPL-2.0 is compatible with this project's MIT license when the MPL-licensed files remain unmodified.
