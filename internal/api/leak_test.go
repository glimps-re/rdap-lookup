// Package api goroutine leak detection.
//
// This file installs a TestMain that verifies no goroutines are leaked after
// the test suite completes. The ignore list below captures goroutines that
// are started by third-party libraries (Prometheus, Echo, net/http transport)
// and are intentionally long-lived; they do NOT indicate leaks from our code.
//
// If a new test introduces a long-lived library goroutine, add it to the
// ignore list with a comment explaining the source.
package api

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	// Ignore list for known long-lived goroutines from third-party libraries.
	// Each entry is verified at authoring time by running the test suite with
	// goleak.VerifyTestMain and inspecting the reported goroutine stacks.
	ignores := []goleak.Option{
		// net/http keep-alive connection management (standard library).
		goleak.IgnoreTopFunction("net/http.(*persistConn).readLoop"),
		goleak.IgnoreTopFunction("net/http.(*persistConn).writeLoop"),
		// Prometheus default gatherer background work (client_golang).
		goleak.IgnoreTopFunction("github.com/prometheus/client_golang/prometheus.(*goCollector).Start.func1"),
		// TestServer_Shutdown starts a real Echo server in a goroutine; the
		// goroutine may still be in Accept() briefly after Shutdown() returns.
		// IgnoreAnyFunction matches anywhere in the call stack.
		goleak.IgnoreAnyFunction("net/http.(*Server).Serve"),
	}

	goleak.VerifyTestMain(m, ignores...)
}
