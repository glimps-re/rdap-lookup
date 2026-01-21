package whois

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple domain", "example.com", "example.com"},
		{"uppercase", "EXAMPLE.COM", "example.com"},
		{"with trailing dot", "example.com.", "example.com"},
		{"with whitespace", "  example.com  ", "example.com"},
		{"subdomain", "www.example.com", "www.example.com"},
		{"empty", "", ""},
		{"single label", "localhost", ""},
		{"mixed case subdomain", "WWW.Example.COM", "www.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeDomain(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeDomain(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestNewClient(t *testing.T) {
	c := NewClient()

	if c.timeout != DefaultQueryTimeout {
		t.Errorf("default timeout = %v, want %v", c.timeout, DefaultQueryTimeout)
	}

	if c.maxResponseSize != DefaultMaxResponseSize {
		t.Errorf("default maxResponseSize = %v, want %v", c.maxResponseSize, DefaultMaxResponseSize)
	}

	if c.discovery == nil {
		t.Error("discovery should not be nil")
	}
}

func TestNewClientWithOptions(t *testing.T) {
	customTimeout := 5 * time.Second
	customMaxSize := int64(128 * 1024)

	c := NewClient(
		WithClientTimeout(customTimeout),
		WithClientMaxResponseSize(customMaxSize),
	)

	if c.timeout != customTimeout {
		t.Errorf("timeout = %v, want %v", c.timeout, customTimeout)
	}

	if c.maxResponseSize != customMaxSize {
		t.Errorf("maxResponseSize = %v, want %v", c.maxResponseSize, customMaxSize)
	}
}

func TestNewClientWithDiscovery(t *testing.T) {
	discovery := NewDiscovery()
	c := NewClient(WithClientDiscovery(discovery))

	if c.discovery != discovery {
		t.Error("discovery should be the provided instance")
	}
}

func TestClient_Query_InvalidDomain(t *testing.T) {
	c := NewClient()
	ctx := context.Background()

	// Empty domain
	_, err := c.Query(ctx, "")
	if err == nil {
		t.Error("expected error for empty domain")
	}

	// Single label (no TLD)
	_, err = c.Query(ctx, "localhost")
	if err == nil {
		t.Error("expected error for single label domain")
	}
}

func TestClient_Query_ClientClosed(t *testing.T) {
	c := NewClient()
	ctx := context.Background()

	// Close the client
	if err := c.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Query should fail
	_, err := c.Query(ctx, "example.com")
	if err == nil {
		t.Error("expected error for closed client")
	}
}

func TestClient_QueryServer_ClientClosed(t *testing.T) {
	c := NewClient()
	ctx := context.Background()

	// Close the client
	if err := c.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// QueryServer should fail
	_, err := c.QueryServer(ctx, "example.com", "whois.example.com")
	if err == nil {
		t.Error("expected error for closed client")
	}
}

func TestClient_Close_Idempotent(t *testing.T) {
	c := NewClient()

	// Close multiple times should not error
	if err := c.Close(); err != nil {
		t.Errorf("first Close() error = %v", err)
	}

	if err := c.Close(); err != nil {
		t.Errorf("second Close() error = %v", err)
	}
}

func TestClient_Discovery(t *testing.T) {
	c := NewClient()

	discovery := c.Discovery()
	if discovery == nil {
		t.Error("Discovery() should not return nil")
	}
}

// mockWHOISServer creates a mock WHOIS server for testing.
type mockWHOISServer struct {
	listener net.Listener
	response string
	delay    time.Duration
	closed   bool
	mu       sync.Mutex
	conns    []net.Conn
}

func newMockWHOISServer(t *testing.T, response string) *mockWHOISServer {
	t.Helper()

	var lc net.ListenConfig
	listener, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}

	server := &mockWHOISServer{
		listener: listener,
		response: response,
	}

	go server.serve()

	return server
}

func (s *mockWHOISServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return // Listener closed
		}

		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = conn.Close()
			return
		}
		s.conns = append(s.conns, conn)
		s.mu.Unlock()

		go s.handleConn(conn)
	}
}

func (s *mockWHOISServer) handleConn(conn net.Conn) {
	defer func() {
		_ = conn.Close()
	}()

	// Read the query
	buf := make([]byte, 256)
	_, err := conn.Read(buf)
	if err != nil {
		return
	}

	// Apply delay if set
	if s.delay > 0 {
		time.Sleep(s.delay)
	}

	// Send response
	_, _ = conn.Write([]byte(s.response))
}

func (s *mockWHOISServer) addr() string {
	return s.listener.Addr().String()
}

func (s *mockWHOISServer) close() {
	s.mu.Lock()
	s.closed = true
	for _, conn := range s.conns {
		_ = conn.Close()
	}
	s.mu.Unlock()
	_ = s.listener.Close()
}

func (s *mockWHOISServer) setDelay(d time.Duration) {
	s.mu.Lock()
	s.delay = d
	s.mu.Unlock()
}

func TestClient_doQuery_Success(t *testing.T) {
	response := `Domain Name: example.com
Registry Domain ID: 12345
Registrar: Example Registrar
Creation Date: 2000-01-01T00:00:00Z
Name Server: ns1.example.com
Name Server: ns2.example.com
`
	server := newMockWHOISServer(t, response)
	defer server.close()

	c := NewClient(WithClientTimeout(5 * time.Second))
	ctx := context.Background()

	// Use doQueryAddr directly with the mock server address
	result, err := c.doQueryAddr(ctx, "example.com", "mock.server", server.addr())
	if err != nil {
		t.Fatalf("doQueryAddr error = %v", err)
	}

	if result != response {
		t.Errorf("response = %q, want %q", result, response)
	}
}

func TestClient_doQuery_Timeout(t *testing.T) {
	server := newMockWHOISServer(t, "response")
	defer server.close()

	// Set server to delay response
	server.setDelay(2 * time.Second)

	c := NewClient(WithClientTimeout(100 * time.Millisecond))

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := c.doQueryAddr(ctx, "example.com", "mock.server", server.addr())
	if err == nil {
		t.Error("expected timeout error")
	}
}

func TestClient_doQuery_ConnectionRefused(t *testing.T) {
	c := NewClient(WithClientTimeout(1 * time.Second))
	ctx := context.Background()

	// Use a port that is definitely not listening
	_, err := c.doQueryAddr(ctx, "example.com", "localhost", "127.0.0.1:65432")
	if err == nil {
		t.Error("expected connection error")
	}

	var whoisErr *WHOISError
	if !errors.As(err, &whoisErr) {
		t.Errorf("expected WHOISError, got %T", err)
	}
}

func TestClient_readResponse_SizeLimit(t *testing.T) {
	// Create a response larger than the limit
	largeResponse := strings.Repeat("x", 100*1024) // 100KB

	server := newMockWHOISServer(t, largeResponse)
	defer server.close()

	// Client with small limit
	c := NewClient(
		WithClientTimeout(5*time.Second),
		WithClientMaxResponseSize(1024), // 1KB limit
	)
	ctx := context.Background()

	_, err := c.doQueryAddr(ctx, "example.com", "mock.server", server.addr())
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Errorf("expected ErrResponseTooLarge, got %v", err)
	}
}

func TestClient_readResponse_ExactLimit(t *testing.T) {
	// Create a response exactly at the limit
	response := strings.Repeat("x", 1024) // 1KB

	server := newMockWHOISServer(t, response)
	defer server.close()

	c := NewClient(
		WithClientTimeout(5*time.Second),
		WithClientMaxResponseSize(1024), // 1KB limit
	)
	ctx := context.Background()

	result, err := c.doQueryAddr(ctx, "example.com", "mock.server", server.addr())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result != response {
		t.Errorf("response length = %d, want %d", len(result), len(response))
	}
}

func TestClient_readResponse_StreamingChunks(t *testing.T) {
	// Test that streaming works correctly with multiple read calls
	c := &Client{
		maxResponseSize: 10 * 1024,
	}

	// Create a reader that returns data in small chunks
	chunks := []string{"Domain: ", "example", ".com\n", "Status: ", "active"}
	reader := &chunkReader{chunks: chunks}

	// Create a mock connection
	mockConn := &mockNetConn{reader: reader}

	response, err := c.readResponse(mockConn, "test.server")
	if err != nil {
		t.Fatalf("readResponse error = %v", err)
	}

	expected := strings.Join(chunks, "")
	if response != expected {
		t.Errorf("response = %q, want %q", response, expected)
	}
}

// chunkReader is a test helper that returns data in small chunks.
type chunkReader struct {
	chunks []string
	index  int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if r.index >= len(r.chunks) {
		return 0, io.EOF
	}
	chunk := r.chunks[r.index]
	r.index++
	n := copy(p, chunk)
	return n, nil
}

// mockNetConn implements net.Conn for testing.
type mockNetConn struct {
	reader io.Reader
}

func (m *mockNetConn) Read(b []byte) (n int, err error)   { return m.reader.Read(b) }
func (m *mockNetConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockNetConn) Close() error                       { return nil }
func (m *mockNetConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (m *mockNetConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (m *mockNetConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockNetConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockNetConn) SetWriteDeadline(t time.Time) error { return nil }

// TestClient_Query_Integration tests actual WHOIS queries.
// This test is skipped by default as it requires network access.
func TestClient_Query_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	c := NewClient(
		WithClientTimeout(30*time.Second),
		WithClientMaxResponseSize(128*1024),
	)
	defer func() {
		_ = c.Close()
	}()

	ctx := context.Background()

	// Test with a well-known domain
	result, err := c.Query(ctx, "google.com")
	if err != nil {
		t.Logf("Note: Could not query WHOIS: %v", err)
		t.Skip("skipping: WHOIS server not reachable")
	}

	if result == nil {
		t.Fatal("result should not be nil")
	}

	if result.Response == "" {
		t.Error("response should not be empty")
	}

	if result.Server == "" {
		t.Error("server should not be empty")
	}

	t.Logf("Queried WHOIS server: %s", result.Server)
	t.Logf("Response length: %d bytes", len(result.Response))
	t.Logf("Duration: %v", result.Duration)

	// Response should contain domain name
	if !strings.Contains(strings.ToLower(result.Response), "google") {
		t.Error("response should contain 'google'")
	}
}

func TestClient_ConcurrentQueries(t *testing.T) {
	response := `Domain Name: test.com
Status: active
`
	server := newMockWHOISServer(t, response)
	defer server.close()

	c := NewClient(WithClientTimeout(5 * time.Second))
	serverAddr := server.addr()

	// Run concurrent queries
	var wg sync.WaitGroup
	errCh := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx := context.Background()
			_, err := c.doQueryAddr(ctx, "test.com", "mock.server", serverAddr)
			if err != nil {
				errCh <- err
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent query error: %v", err)
	}
}
