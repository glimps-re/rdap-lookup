# Fix: concurrent map writes panic

**Branch:** `fix/concurrent-map-writes`
**Merged from:** feature branch PR

## Root cause

Under sustained load with HTTP/1.1 keep-alive clients, rdap-lookup panicked
with `fatal error: concurrent map writes` on the Echo response-header map.

Echo reuses a pooled `*echo.Response` for a new keep-alive request while a
previous request's handler goroutine is still alive and writing to the same
header map. The handler goroutine outlived its request because
`middleware.TimeoutWithConfig` (`http.TimeoutHandler` internally) returns 503
to the client but cannot stop the inner goroutine — it runs until upstream I/O
(WHOIS TCP dial, RDAP HTTP) returns.

## Fix (three parts, all required)

### 1. Detach singleflight fetch context from caller (`internal/cache/tiered.go`)

Inside `GetOrFetch` / `GetOrFetchWithNegative`, the fetch closure now receives
a context derived from `context.WithoutCancel(callerCtx)` capped by
`TieredCacheConfig.FetchTimeout`. The caller context is still used for the
initial cache probe; only the upstream fetch is detached. This prevents the
flight owner's cancellation from aborting joined callers.

### 2. Per-handler `context.WithTimeout` in every lookup endpoint (`internal/api/lookup.go`)

Each of `LookupDomain`, `LookupIP`, `LookupASN`, `LookupEntity`, `LookupBatch`
derives a handler-scoped timeout from `LookupHandler.handlerTimeout` (sourced
from `cfg.Server.WriteTimeout`). Upstream I/O is now guaranteed to cancel when
the handler timeout fires, so the goroutine exits promptly.

### 3. Remove `middleware.TimeoutWithConfig` (`internal/api/server.go`)

The `http.TimeoutHandler` wrapper was the root enabler of the goroutine leak.
With per-handler cancellation in place it is redundant and harmful (masks the
true handler state). Deleted.

## Regression harness

- `internal/api/leak_test.go` — `goleak.VerifyTestMain` for the api package.
- `internal/api/race_test.go` — 20 concurrent goroutines × 10 keep-alive
  requests against a pre-warmed cache; `-race` detector validates no
  concurrent header-map writes.
- `internal/whois/leak_test.go` — blackhole TCP listener (read-hang path) and
  TEST-NET-1 dial target (dial-hang path); `goleak.VerifyNone` confirms no
  goroutine leak after context cancellation.

## Rate limiter audit

`IPRateLimiter` (`internal/api/ratelimit.go`) was audited for the same class
of bug. No exposure found: `sync.Map` + per-entry `sync.Mutex`, `atomic.Bool`
counters, `cleanupLoop` holds no `echo.Context`. See `tmp/RATE_LIMIT_AUDIT.md`.

## Out-of-scope follow-up

`rdap.Client.resolver` pointer swap at `internal/rdap/client.go:160-162` is
an unsynchronised write visible from detached fetch goroutines. Fix with
`atomic.Pointer[bootstrap.Resolver]` in a separate PR before enabling
high-concurrency deployments.
