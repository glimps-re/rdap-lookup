package whois

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// Client Benchmarks
// ============================================================================

// BenchmarkClient_doQueryAddr benchmarks the core WHOIS query functionality.
func BenchmarkClient_doQueryAddr(b *testing.B) {
	response := `Domain Name: example.com
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.registrar.com
Registrar URL: http://www.registrar.com
Updated Date: 2024-01-15T10:30:00Z
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2025-08-13T04:00:00Z
Registrar: Example Registrar, Inc.
Registrar IANA ID: 9999
Registrar Abuse Contact Email: abuse@registrar.com
Registrar Abuse Contact Phone: +1.5555551234
Domain Status: clientTransferProhibited
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
DNSSEC: unsigned
`

	server := newBenchmarkWHOISServer(b, response)
	defer server.close()

	c := NewClient(
		WithClientTimeout(5*time.Second),
		WithClientMaxResponseSize(DefaultMaxResponseSize),
	)
	ctx := context.Background()
	addr := server.addr()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := c.doQueryAddr(ctx, "example.com", "mock.server", addr)
		if err != nil {
			b.Fatalf("doQueryAddr error = %v", err)
		}
	}
}

// BenchmarkClient_doQueryAddr_LargeResponse benchmarks parsing larger WHOIS responses.
func BenchmarkClient_doQueryAddr_LargeResponse(b *testing.B) {
	// Build a larger response typical of verbose registries
	var sb strings.Builder
	sb.WriteString("Domain Name: example.com\n")
	sb.WriteString("Registry Domain ID: 2336799_DOMAIN_COM-VRSN\n")
	for i := 0; i < 50; i++ {
		sb.WriteString("Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\n")
	}
	for i := 0; i < 10; i++ {
		sb.WriteString("Name Server: NS")
		sb.WriteRune(rune('1' + i))
		sb.WriteString(".EXAMPLE.COM\n")
	}
	sb.WriteString(">>> Last update of WHOIS database: 2024-01-15T10:30:00Z <<<\n")
	sb.WriteString(strings.Repeat("% Terms of service notice\n", 20))

	response := sb.String()

	server := newBenchmarkWHOISServer(b, response)
	defer server.close()

	c := NewClient(
		WithClientTimeout(5*time.Second),
		WithClientMaxResponseSize(DefaultMaxResponseSize),
	)
	ctx := context.Background()
	addr := server.addr()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := c.doQueryAddr(ctx, "example.com", "mock.server", addr)
		if err != nil {
			b.Fatalf("doQueryAddr error = %v", err)
		}
	}
}

// BenchmarkClient_readResponse benchmarks the streaming response reader.
func BenchmarkClient_readResponse(b *testing.B) {
	response := strings.Repeat("x", 8*1024) // 8KB typical response

	c := &Client{
		maxResponseSize: DefaultMaxResponseSize,
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		mockConn := &benchmarkMockConn{data: response, pos: 0}
		_, err := c.readResponse(mockConn, "test.server")
		if err != nil {
			b.Fatalf("readResponse error = %v", err)
		}
	}
}

// BenchmarkClient_Parallel_doQueryAddr benchmarks concurrent WHOIS queries.
func BenchmarkClient_Parallel_doQueryAddr(b *testing.B) {
	response := `Domain Name: example.com
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
Registrar: Example Registrar
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
`

	server := newBenchmarkWHOISServer(b, response)
	defer server.close()

	c := NewClient(
		WithClientTimeout(5*time.Second),
		WithClientMaxResponseSize(DefaultMaxResponseSize),
	)
	ctx := context.Background()
	addr := server.addr()

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := c.doQueryAddr(ctx, "example.com", "mock.server", addr)
			if err != nil {
				b.Fatalf("doQueryAddr error = %v", err)
			}
		}
	})
}

// BenchmarkNormalizeDomain benchmarks domain normalization.
func BenchmarkNormalizeDomain(b *testing.B) {
	domains := []string{
		"example.com",
		"EXAMPLE.COM",
		"  Example.Com  ",
		"example.com.",
		"www.example.com",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = normalizeDomain(domains[i%len(domains)])
	}
}

// ============================================================================
// Parser Registry Benchmarks
// ============================================================================

// BenchmarkParserRegistry_GetParser benchmarks parser lookup performance.
func BenchmarkParserRegistry_GetParser(b *testing.B) {
	registry := NewParserRegistry()

	// Register some mock parsers
	for _, tld := range []string{"de", "cn", "ru", "au", "eu", "it", "es", "jp"} {
		registry.Register(NewGenericParser(), tld)
	}

	tlds := []string{"de", "cn", "ru", "au", "eu", "it", "es", "jp", "com", "org", "net", "unknown"}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = registry.GetParser(tlds[i%len(tlds)])
	}
}

// BenchmarkParserRegistry_Parse benchmarks the full registry parse flow.
func BenchmarkParserRegistry_Parse(b *testing.B) {
	registry := NewParserRegistry()

	response := `Domain Name: example.com
Registrar: Example Registrar
Creation Date: 2000-01-01T00:00:00Z
Name Server: ns1.example.com
Name Server: ns2.example.com
`

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = registry.Parse(response, "example.com")
	}
}

// ============================================================================
// Field Extractor Benchmarks
// ============================================================================

// BenchmarkFieldExtractor_Extract benchmarks single field extraction.
func BenchmarkFieldExtractor_Extract(b *testing.B) {
	extractor := newFieldExtractor(
		"Domain Name",
		"Domain",
		"domain name",
	)

	response := `Domain Name: example.com
Registrar WHOIS Server: whois.example.com
Registrar URL: http://www.example.com
Updated Date: 2024-01-15T10:30:00Z
Creation Date: 1995-08-14T04:00:00Z
`

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = extractor.Extract(response)
	}
}

// BenchmarkFieldExtractor_ExtractAll benchmarks multi-value field extraction.
func BenchmarkFieldExtractor_ExtractAll(b *testing.B) {
	extractor := newFieldExtractor(
		"Name Server",
		"Nameserver",
		"nserver",
	)

	response := `Domain Name: example.com
Name Server: ns1.example.com
Name Server: ns2.example.com
Name Server: ns3.example.com
Name Server: ns4.example.com
`

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = extractor.ExtractAll(response)
	}
}

// ============================================================================
// TLD Extraction Benchmarks
// ============================================================================

// BenchmarkExtractTLD benchmarks TLD extraction from domains.
func BenchmarkExtractTLD(b *testing.B) {
	domains := []string{
		"example.com",
		"www.example.co.uk",
		"test.example.com.au",
		"mail.server.example.de",
		"sub.domain.example.jp",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = ExtractTLD(domains[i%len(domains)])
	}
}

// BenchmarkNormalizeTLD benchmarks TLD normalization.
func BenchmarkNormalizeTLD(b *testing.B) {
	tlds := []string{"COM", "co.uk", "COM.AU", "De", "JP"}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = normalizeTLD(tlds[i%len(tlds)])
	}
}

// ============================================================================
// Composite Benchmarks
// ============================================================================

// BenchmarkFullPipeline benchmarks the complete WHOIS lookup and parse pipeline.
func BenchmarkFullPipeline(b *testing.B) {
	response := `Domain Name: example.de
Nserver: ns1.example.de
Nserver: ns2.example.de
Status: connect
Changed: 2024-01-15T10:30:00+01:00
RegCreatedDate: 2000-05-20T00:00:00+02:00

[Holder]
Type: PERSON
Name: John Doe
Organisation: Example GmbH
Email: holder@example.de
`

	server := newBenchmarkWHOISServer(b, response)
	defer server.close()

	c := NewClient(
		WithClientTimeout(5*time.Second),
		WithClientMaxResponseSize(DefaultMaxResponseSize),
	)
	registry := NewParserRegistry()
	ctx := context.Background()
	addr := server.addr()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Query
		result, err := c.doQueryAddr(ctx, "example.de", "mock.server", addr)
		if err != nil {
			b.Fatalf("query error = %v", err)
		}

		// Parse
		parseResult, err := registry.Parse(result, "example.de")
		if err != nil {
			b.Fatalf("parse error = %v", err)
		}

		// Transform
		_ = TransformToSimpleDomain(parseResult)
	}
}

// BenchmarkFullPipeline_Parallel benchmarks concurrent full pipeline execution.
func BenchmarkFullPipeline_Parallel(b *testing.B) {
	response := `Domain Name: example.com
Registrar: Example Registrar
Creation Date: 2000-01-01T00:00:00Z
Name Server: ns1.example.com
Name Server: ns2.example.com
`

	server := newBenchmarkWHOISServer(b, response)
	defer server.close()

	c := NewClient(
		WithClientTimeout(5*time.Second),
		WithClientMaxResponseSize(DefaultMaxResponseSize),
	)
	registry := NewParserRegistry()
	ctx := context.Background()
	addr := server.addr()

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			result, err := c.doQueryAddr(ctx, "example.com", "mock.server", addr)
			if err != nil {
				b.Fatalf("query error = %v", err)
			}

			parseResult, err := registry.Parse(result, "example.com")
			if err != nil {
				b.Fatalf("parse error = %v", err)
			}

			_ = TransformToSimpleDomain(parseResult)
		}
	})
}

// ============================================================================
// Benchmark Helpers
// ============================================================================

// benchmarkWHOISServer is a minimal mock server for benchmarks.
type benchmarkWHOISServer struct {
	listener net.Listener
	response string
	mu       sync.Mutex
	closed   bool
}

func newBenchmarkWHOISServer(b *testing.B, response string) *benchmarkWHOISServer {
	b.Helper()

	var lc net.ListenConfig
	listener, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("failed to create listener: %v", err)
	}

	server := &benchmarkWHOISServer{
		listener: listener,
		response: response,
	}

	go server.serve()

	return server
}

func (s *benchmarkWHOISServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}

		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = conn.Close()
			return
		}
		s.mu.Unlock()

		go s.handleConn(conn)
	}
}

func (s *benchmarkWHOISServer) handleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	buf := make([]byte, 256)
	_, _ = conn.Read(buf)
	_, _ = conn.Write([]byte(s.response))
}

func (s *benchmarkWHOISServer) addr() string {
	return s.listener.Addr().String()
}

func (s *benchmarkWHOISServer) close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	_ = s.listener.Close()
}

// benchmarkMockConn is a minimal mock net.Conn for benchmarks.
type benchmarkMockConn struct {
	data string
	pos  int
}

func (m *benchmarkMockConn) Read(b []byte) (int, error) {
	if m.pos >= len(m.data) {
		return 0, io.EOF
	}
	n := copy(b, m.data[m.pos:])
	m.pos += n
	return n, nil
}

func (m *benchmarkMockConn) Write(b []byte) (int, error)      { return len(b), nil }
func (m *benchmarkMockConn) Close() error                     { return nil }
func (m *benchmarkMockConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (m *benchmarkMockConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (m *benchmarkMockConn) SetDeadline(time.Time) error      { return nil }
func (m *benchmarkMockConn) SetReadDeadline(time.Time) error  { return nil }
func (m *benchmarkMockConn) SetWriteDeadline(time.Time) error { return nil }
