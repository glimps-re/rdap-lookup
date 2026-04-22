// Goroutine leak regression tests for the WHOIS client.
//
// These tests verify that the WHOIS client does not leak goroutines when
// upstream servers are slow or unresponsive. They cover two code paths:
//
//  1. Read-hang path: a TCP server that accepts connections but never sends
//     data, exercising c.readResponse blocking.
//  2. Dial-hang path: a TCP server that binds a port but never calls Accept,
//     so DialContext blocks until the context deadline fires.
//
// Both paths must resolve promptly when the context is cancelled.
package whois

import (
	"context"
	"net"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/glimps-re/rdap-lookup/internal/config"
)

// blackholeListener binds a TCP listener and accepts connections without
// reading or writing any data. It is used to exercise the read-hang path.
type blackholeListener struct {
	l net.Listener
}

func newBlackholeListener(t *testing.T) *blackholeListener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return &blackholeListener{l: l}
}

// Addr returns the listener address (host:port string).
func (b *blackholeListener) Addr() string {
	return b.l.Addr().String()
}

// AcceptForever accepts connections and keeps them open without reading.
// Call this in a goroutine; it exits when the listener is closed.
func (b *blackholeListener) AcceptForever() {
	for {
		conn, err := b.l.Accept()
		if err != nil {
			return
		}
		// Intentionally do nothing: hold the connection open so the client
		// blocks in readResponse, exercising the read-hang path.
		_ = conn
	}
}

// TestWHOISClient_ReadHang_ContextCancels verifies that when a WHOIS server
// accepts a connection but never sends data, the client goroutine exits
// promptly once the context deadline fires (no goroutine leak).
func TestWHOISClient_ReadHang_ContextCancels(t *testing.T) {
	const handlerTimeout = 100 * time.Millisecond

	// Capture any goroutines already running before this test (e.g. mock server
	// goroutines from other tests in this package) so they don't pollute the
	// leak check at the end of this test.
	ignore := goleak.IgnoreCurrent()

	bl := newBlackholeListener(t)
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		bl.AcceptForever()
	}()

	cfg := config.WHOISConfig{
		Enabled:         true,
		Timeout:         5 * time.Second, // client-level timeout, longer than handler
		MaxResponseSize: 64 * 1024,
	}
	client := NewClientFromConfig(cfg, nil)
	defer func() { _ = client.Close() }()

	// Derive a context with a short deadline to simulate handler timeout.
	ctx, cancel := context.WithTimeout(context.Background(), handlerTimeout)
	defer cancel()

	host, port, _ := net.SplitHostPort(bl.Addr())
	start := time.Now()
	_, err := client.doQueryAddr(ctx, "example.test", host, net.JoinHostPort(host, port))
	elapsed := time.Since(start)

	if err == nil {
		t.Error("expected error from blackhole server, got nil")
	}

	// Client must return within handlerTimeout + generous buffer.
	if elapsed > handlerTimeout+500*time.Millisecond {
		t.Errorf("doQueryAddr took %v, want < %v", elapsed, handlerTimeout+500*time.Millisecond)
	}

	// Close the blackhole listener to stop AcceptForever before leak check.
	_ = bl.l.Close()
	<-acceptDone

	// After return, no goroutine should be leaking inside doQueryAddr.
	goleak.VerifyNone(t, ignore,
		goleak.IgnoreTopFunction("net/http.(*persistConn).readLoop"),
		goleak.IgnoreTopFunction("net/http.(*persistConn).writeLoop"),
	)
}

// TestWHOISClient_SlowDial_ContextCancels verifies that a context cancellation
// during DialContext causes the client to return promptly (no goroutine leak).
// Uses TEST-NET-1 (192.0.2.1) which is non-routable so DialContext blocks
// until the context deadline or the OS TCP timeout fires.
func TestWHOISClient_SlowDial_ContextCancels(t *testing.T) {
	const handlerTimeout = 100 * time.Millisecond

	// Capture pre-existing goroutines (e.g. mock server goroutines from
	// earlier tests in this package) to avoid false leak reports.
	ignore := goleak.IgnoreCurrent()

	cfg := config.WHOISConfig{
		Enabled:         true,
		Timeout:         5 * time.Second,
		MaxResponseSize: 64 * 1024,
	}
	client := NewClientFromConfig(cfg, nil)
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), handlerTimeout)
	defer cancel()

	// 192.0.2.1 is TEST-NET-1 (RFC 5737), guaranteed non-routable; DialContext
	// blocks until the context deadline rather than refusing immediately.
	start := time.Now()
	_, err := client.doQueryAddr(ctx, "example.test", "192.0.2.1", "192.0.2.1:43")
	elapsed := time.Since(start)

	if err == nil {
		t.Error("expected error dialing non-routable address, got nil")
	}

	// Must return within handlerTimeout + generous buffer.
	if elapsed > handlerTimeout+500*time.Millisecond {
		t.Errorf("doQueryAddr took %v, want < %v", elapsed, handlerTimeout+500*time.Millisecond)
	}

	goleak.VerifyNone(t, ignore,
		goleak.IgnoreTopFunction("net/http.(*persistConn).readLoop"),
		goleak.IgnoreTopFunction("net/http.(*persistConn).writeLoop"),
	)
}
