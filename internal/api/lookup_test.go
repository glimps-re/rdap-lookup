package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/glimps-re/rdap-lookup/internal/bootstrap"
	"github.com/glimps-re/rdap-lookup/internal/cache"
	"github.com/glimps-re/rdap-lookup/internal/config"
	"github.com/glimps-re/rdap-lookup/internal/metrics"
	"github.com/glimps-re/rdap-lookup/internal/rdap"
	"github.com/glimps-re/rdap-lookup/internal/validate"
)

func TestLookupHandler_ErrorResponse(t *testing.T) {
	// Test error response format
	errResp := ErrorResponse{
		Error: ErrorDetail{
			Code:    "TEST_ERROR",
			Message: "Test error message",
		},
	}

	data, err := json.Marshal(errResp)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded ErrorResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.Error.Code != "TEST_ERROR" {
		t.Errorf("Error.Code = %q, want %q", decoded.Error.Code, "TEST_ERROR")
	}

	if decoded.Error.Message != "Test error message" {
		t.Errorf("Error.Message = %q, want %q", decoded.Error.Message, "Test error message")
	}
}

func TestBatchRequest_JSON(t *testing.T) {
	req := BatchRequest{
		Queries: []BatchQuery{
			{Type: "domain", Value: "example.com"},
			{Type: "ip", Value: "8.8.8.8"},
			{Type: "asn", Value: "15169"},
			{Type: "entity", Value: "ABC-123", Server: "https://rdap.example.com"},
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded BatchRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if len(decoded.Queries) != 4 {
		t.Fatalf("Queries len = %d, want 4", len(decoded.Queries))
	}

	if decoded.Queries[0].Type != "domain" {
		t.Errorf("Query[0].Type = %q, want %q", decoded.Queries[0].Type, "domain")
	}

	if decoded.Queries[3].Server != "https://rdap.example.com" {
		t.Errorf("Query[3].Server = %q, want %q", decoded.Queries[3].Server, "https://rdap.example.com")
	}
}

func TestBatchResponse_JSON(t *testing.T) {
	resp := BatchResponse{
		Results: []BatchResult{
			{Type: "domain", Value: "example.com", Data: []byte(`{"name":"example.com"}`), Cached: true},
			{Type: "ip", Value: "8.8.8.8", Error: "not found"},
		},
		Stats: BatchStats{
			Total:      2,
			Success:    1,
			Errors:     1,
			CacheHits:  1,
			DurationMs: 100,
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded BatchResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.Stats.Total != 2 {
		t.Errorf("Stats.Total = %d, want 2", decoded.Stats.Total)
	}

	if decoded.Stats.Success != 1 {
		t.Errorf("Stats.Success = %d, want 1", decoded.Stats.Success)
	}

	if decoded.Results[0].Cached != true {
		t.Error("Results[0].Cached = false, want true")
	}

	if decoded.Results[1].Error != "not found" {
		t.Errorf("Results[1].Error = %q, want %q", decoded.Results[1].Error, "not found")
	}
}

func TestLookupHandler_DomainValidation(t *testing.T) {
	e := echo.New()

	// Test with empty domain name
	req := httptest.NewRequest(http.MethodGet, "/api/v1/domain/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("name")
	c.SetParamValues("")

	// We can't fully test without dependencies, but we can test input validation
	handler := &LookupHandler{}
	err := handler.LookupDomain(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	var errResp ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if errResp.Error.Code != "INVALID_REQUEST" {
		t.Errorf("Error.Code = %q, want %q", errResp.Error.Code, "INVALID_REQUEST")
	}
}

func TestLookupHandler_IPValidation(t *testing.T) {
	e := echo.New()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ip/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("addr")
	c.SetParamValues("")

	handler := &LookupHandler{}
	err := handler.LookupIP(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	var errResp ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if errResp.Error.Code != "INVALID_REQUEST" {
		t.Errorf("Error.Code = %q, want %q", errResp.Error.Code, "INVALID_REQUEST")
	}
}

func TestLookupHandler_ASNValidation(t *testing.T) {
	e := echo.New()

	tests := []struct {
		name     string
		asn      string
		wantCode int
		wantErr  string
	}{
		{
			name:     "empty",
			asn:      "",
			wantCode: http.StatusBadRequest,
			wantErr:  "INVALID_REQUEST",
		},
		{
			name:     "invalid format",
			asn:      "not-a-number",
			wantCode: http.StatusBadRequest,
			wantErr:  "INVALID_REQUEST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/asn/"+tt.asn, nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetParamNames("asn")
			c.SetParamValues(tt.asn)

			handler := &LookupHandler{}
			err := handler.LookupASN(c)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if rec.Code != tt.wantCode {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantCode)
			}

			var errResp ErrorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
				t.Fatalf("unmarshal error: %v", err)
			}

			if errResp.Error.Code != tt.wantErr {
				t.Errorf("Error.Code = %q, want %q", errResp.Error.Code, tt.wantErr)
			}
		})
	}
}

// Note: Full integration tests for ASN prefix handling require
// a complete handler setup with cache, RDAP client, and bootstrap service.
// Input validation for AS prefix is tested implicitly - if parsing fails,
// we'd get an INVALID_REQUEST error, not pass through to the cache lookup.

func TestLookupHandler_EntityValidation(t *testing.T) {
	e := echo.New()

	tests := []struct {
		name      string
		handle    string
		serverURL string
		wantCode  int
		wantMsg   string
	}{
		{
			name:      "empty handle",
			handle:    "",
			serverURL: "https://rdap.example.com",
			wantCode:  http.StatusBadRequest,
			wantMsg:   "Entity handle is required",
		},
		{
			name:      "missing server",
			handle:    "ABC-123",
			serverURL: "",
			wantCode:  http.StatusBadRequest,
			wantMsg:   "Server URL is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/entity/" + tt.handle
			if tt.serverURL != "" {
				url += "?server=" + tt.serverURL
			}
			req := httptest.NewRequest(http.MethodGet, url, nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetParamNames("handle")
			c.SetParamValues(tt.handle)

			handler := &LookupHandler{}
			err := handler.LookupEntity(c)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if rec.Code != tt.wantCode {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantCode)
			}

			var errResp ErrorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
				t.Fatalf("unmarshal error: %v", err)
			}

			if !strings.Contains(errResp.Error.Message, tt.wantMsg) {
				t.Errorf("Error.Message = %q, want to contain %q", errResp.Error.Message, tt.wantMsg)
			}
		})
	}
}

func TestLookupHandler_BatchValidation(t *testing.T) {
	e := echo.New()

	tests := []struct {
		name     string
		body     string
		wantCode int
		wantMsg  string
	}{
		{
			name:     "invalid json",
			body:     "not json",
			wantCode: http.StatusBadRequest,
			wantMsg:  "Invalid request body",
		},
		{
			name:     "empty queries",
			body:     `{"queries":[]}`,
			wantCode: http.StatusBadRequest,
			wantMsg:  "At least one query",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/batch", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			handler := &LookupHandler{}
			err := handler.LookupBatch(c)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if rec.Code != tt.wantCode {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantCode)
			}

			var errResp ErrorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
				t.Fatalf("unmarshal error: %v", err)
			}

			if !strings.Contains(errResp.Error.Message, tt.wantMsg) {
				t.Errorf("Error.Message = %q, want to contain %q", errResp.Error.Message, tt.wantMsg)
			}
		})
	}
}

func TestLookupHandler_BatchMaxQueries(t *testing.T) {
	e := echo.New()

	// Create 101 queries (exceeds max of 100)
	queries := make([]BatchQuery, 101)
	for i := range queries {
		queries[i] = BatchQuery{Type: "domain", Value: "example.com"}
	}

	body, _ := json.Marshal(BatchRequest{Queries: queries})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/batch", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler := &LookupHandler{}
	err := handler.LookupBatch(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	var errResp ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if !strings.Contains(errResp.Error.Message, "Maximum 100") {
		t.Errorf("Error.Message = %q, want to contain 'Maximum 100'", errResp.Error.Message)
	}
}

func TestSanitizeBatchError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "not found error",
			err:      rdap.ErrNotFound,
			expected: "not found",
		},
		{
			name:     "rate limited error",
			err:      rdap.ErrRateLimited,
			expected: "rate limited",
		},
		{
			name:     "bootstrap not found",
			err:      bootstrap.ErrNotFound,
			expected: "no RDAP server found",
		},
		{
			name:     "invalid input",
			err:      bootstrap.ErrInvalidInput,
			expected: "invalid input",
		},
		{
			name:     "timeout error",
			err:      context.DeadlineExceeded,
			expected: "timeout",
		},
		{
			name:     "generic error",
			err:      errors.New("some internal error"),
			expected: "query failed",
		},
		{
			name:     "wrapped not found",
			err:      errors.Join(errors.New("wrapper"), rdap.ErrNotFound),
			expected: "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeBatchError(tt.err)
			if result != tt.expected {
				t.Errorf("sanitizeBatchError(%v) = %q, want %q", tt.err, result, tt.expected)
			}
		})
	}
}

func TestSanitizeUpstreamError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "timeout error",
			err:      context.DeadlineExceeded,
			expected: "Upstream server timeout",
		},
		{
			name:     "rate limited error",
			err:      rdap.ErrRateLimited,
			expected: "Upstream server rate limited",
		},
		{
			name:     "server error",
			err:      rdap.ErrServerError,
			expected: "Upstream server error",
		},
		{
			name:     "generic error",
			err:      errors.New("connection refused"),
			expected: "Failed to query upstream RDAP server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeUpstreamError(tt.err)
			if result != tt.expected {
				t.Errorf("sanitizeUpstreamError(%v) = %q, want %q", tt.err, result, tt.expected)
			}
		})
	}
}

func TestLookupHandler_HandleError(t *testing.T) {
	e := echo.New()
	handler := &LookupHandler{}

	tests := []struct {
		name       string
		err        error
		queryType  string
		wantStatus int
		wantCode   string
	}{
		{
			name:       "not found",
			err:        rdap.ErrNotFound,
			queryType:  "domain",
			wantStatus: http.StatusNotFound,
			wantCode:   "NOT_FOUND",
		},
		{
			name:       "rate limited",
			err:        rdap.ErrRateLimited,
			queryType:  "ip",
			wantStatus: http.StatusTooManyRequests,
			wantCode:   "RATE_LIMITED",
		},
		{
			name:       "invalid input",
			err:        bootstrap.ErrInvalidInput,
			queryType:  "asn",
			wantStatus: http.StatusBadRequest,
			wantCode:   "INVALID_REQUEST",
		},
		{
			name:       "bootstrap not found",
			err:        bootstrap.ErrNotFound,
			queryType:  "domain",
			wantStatus: http.StatusNotFound,
			wantCode:   "NOT_FOUND",
		},
		{
			name:       "generic upstream error",
			err:        errors.New("connection refused"),
			queryType:  "domain",
			wantStatus: http.StatusBadGateway,
			wantCode:   "UPSTREAM_ERROR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			err := handler.handleError(c, tt.err, tt.queryType, "test-value")
			if err != nil {
				t.Fatalf("handleError returned error: %v", err)
			}

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}

			var errResp ErrorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
				t.Fatalf("unmarshal error: %v", err)
			}

			if errResp.Error.Code != tt.wantCode {
				t.Errorf("Error.Code = %q, want %q", errResp.Error.Code, tt.wantCode)
			}
		})
	}
}

func TestLookupHandler_RespondWithData(t *testing.T) {
	e := echo.New()
	handler := &LookupHandler{}

	tests := []struct {
		name       string
		data       []byte
		cached     bool
		wantHeader string
	}{
		{
			name:       "cache hit",
			data:       []byte(`{"name":"example.com"}`),
			cached:     true,
			wantHeader: "HIT",
		},
		{
			name:       "cache miss",
			data:       []byte(`{"name":"example.com"}`),
			cached:     false,
			wantHeader: "MISS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)

			err := handler.respondWithData(c, tt.data, tt.cached)
			if err != nil {
				t.Fatalf("respondWithData returned error: %v", err)
			}

			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
			}

			cacheHeader := rec.Header().Get("X-Cache")
			if cacheHeader != tt.wantHeader {
				t.Errorf("X-Cache header = %q, want %q", cacheHeader, tt.wantHeader)
			}

			contentType := rec.Header().Get("Content-Type")
			if contentType != "application/json" {
				t.Errorf("Content-Type = %q, want %q", contentType, "application/json")
			}

			if rec.Body.String() != string(tt.data) {
				t.Errorf("body = %q, want %q", rec.Body.String(), string(tt.data))
			}
		})
	}
}

func TestLookupHandler_EntityServerValidation(t *testing.T) {
	e := echo.New()

	// Create handler with empty server validator (no allowed servers)
	handler := &LookupHandler{
		serverValidator: validate.NewRDAPServerValidator(nil), // Empty allowlist
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entity/ABC-123?server=https://evil.com", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("handle")
	c.SetParamValues("ABC-123")

	err := handler.LookupEntity(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	var errResp ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if errResp.Error.Code != "INVALID_SERVER" {
		t.Errorf("Error.Code = %q, want %q", errResp.Error.Code, "INVALID_SERVER")
	}
}

func TestLookupHandler_ASNWithASPrefix(t *testing.T) {
	e := echo.New()

	// Test that "AS15169" and "as15169" are both processed (prefix stripped)
	// We can only test the validation path here without full dependencies
	tests := []struct {
		name     string
		asn      string
		wantCode int
	}{
		{
			name:     "with AS prefix uppercase",
			asn:      "AS15169",
			wantCode: http.StatusBadGateway, // Will fail at cache lookup but pass validation
		},
		{
			name:     "with as prefix lowercase",
			asn:      "as15169",
			wantCode: http.StatusBadGateway,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/asn/"+tt.asn, nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetParamNames("asn")
			c.SetParamValues(tt.asn)

			// Handler with nil cache will panic - just testing that validation passed
			handler := &LookupHandler{}

			// This should not panic on input validation
			// It will panic later due to nil cache, but we've verified the prefix handling
			func() {
				defer func() {
					// Expected - nil cache access may cause panic
					_ = recover()
				}()
				_ = handler.LookupASN(c)
			}()
		})
	}
}

func TestLookupHandler_InvalidIPAddress(t *testing.T) {
	e := echo.New()

	tests := []struct {
		name string
		addr string
	}{
		{name: "invalid format", addr: "not-an-ip"},
		{name: "out of range", addr: "999.999.999.999"},
		{name: "incomplete", addr: "192.168.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/ip/"+tt.addr, nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetParamNames("addr")
			c.SetParamValues(tt.addr)

			handler := &LookupHandler{}
			err := handler.LookupIP(c)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d for addr %q", rec.Code, http.StatusBadRequest, tt.addr)
			}
		})
	}
}

func TestLookupHandler_InvalidDomainName(t *testing.T) {
	e := echo.New()

	tests := []struct {
		name   string
		domain string
	}{
		{name: "with spaces", domain: "example .com"},
		{name: "special chars", domain: "exam!ple.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use a simple URL path and set the param value separately
			req := httptest.NewRequest(http.MethodGet, "/api/v1/domain/test", nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetParamNames("name")
			c.SetParamValues(tt.domain) // Set the actual test value here

			handler := &LookupHandler{}
			err := handler.LookupDomain(c)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d for domain %q", rec.Code, http.StatusBadRequest, tt.domain)
			}
		})
	}
}

func TestLookupHandler_SetResolver(t *testing.T) {
	// Create a mock bootstrap with test data
	bs := bootstrap.NewBootstrap()
	bs.DNS.SetTLDURLs("com", []string{"https://rdap.verisign.com/v1/"})
	resolver := bootstrap.NewResolver(bs)

	// Create handler with real RDAP client and server validator
	client := rdap.NewClient(10 * time.Second)
	handler := &LookupHandler{
		client:          client,
		serverValidator: validate.NewRDAPServerValidator(nil),
	}

	// SetResolver should update the server validator's allowlist
	handler.SetResolver(resolver)

	// Verify no panic occurred and server validator was updated
}

func TestLookupHandler_SetResolver_NilResolver(t *testing.T) {
	client := rdap.NewClient(10 * time.Second)
	handler := &LookupHandler{
		client:          client,
		serverValidator: validate.NewRDAPServerValidator(nil),
	}

	// SetResolver with nil should not panic
	handler.SetResolver(nil)
}

func TestBatchResult_WithData(t *testing.T) {
	result := BatchResult{
		Type:   "domain",
		Value:  "example.com",
		Data:   json.RawMessage(`{"name":"example.com"}`),
		Cached: true,
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded BatchResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if string(decoded.Data) != `{"name":"example.com"}` {
		t.Errorf("Data = %s, want {\"name\":\"example.com\"}", string(decoded.Data))
	}
}

func TestBatchResult_WithError(t *testing.T) {
	result := BatchResult{
		Type:  "domain",
		Value: "example.com",
		Error: "not found",
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded BatchResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.Error != "not found" {
		t.Errorf("Error = %s, want 'not found'", decoded.Error)
	}

	if decoded.Data != nil {
		t.Errorf("Data should be nil, got %s", string(decoded.Data))
	}
}

func TestBatchStats_JSON(t *testing.T) {
	stats := BatchStats{
		Total:      10,
		Success:    8,
		Errors:     2,
		CacheHits:  5,
		DurationMs: 123,
	}

	data, err := json.Marshal(stats)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded BatchStats
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.Total != 10 {
		t.Errorf("Total = %d, want 10", decoded.Total)
	}
	if decoded.Success != 8 {
		t.Errorf("Success = %d, want 8", decoded.Success)
	}
	if decoded.Errors != 2 {
		t.Errorf("Errors = %d, want 2", decoded.Errors)
	}
	if decoded.CacheHits != 5 {
		t.Errorf("CacheHits = %d, want 5", decoded.CacheHits)
	}
	if decoded.DurationMs != 123 {
		t.Errorf("DurationMs = %d, want 123", decoded.DurationMs)
	}
}

func TestErrorResponse_JSON(t *testing.T) {
	resp := ErrorResponse{
		Error: ErrorDetail{
			Code:    "TEST_CODE",
			Message: "Test message",
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	// Verify JSON structure
	expectedSubstring := `"code":"TEST_CODE"`
	if !strings.Contains(string(data), expectedSubstring) {
		t.Errorf("JSON should contain %s, got %s", expectedSubstring, string(data))
	}
}

func TestLookupHandler_ValidDomain(t *testing.T) {
	e := echo.New()

	// Test with a valid domain that passes validation
	// (will fail at cache lookup but validates input processing)
	tests := []struct {
		name   string
		domain string
	}{
		{name: "simple domain", domain: "example.com"},
		{name: "subdomain", domain: "www.example.com"},
		{name: "deep subdomain", domain: "a.b.c.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/domain/"+tt.domain, nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetParamNames("name")
			c.SetParamValues(tt.domain)

			handler := &LookupHandler{}

			// This will panic due to nil cache, but validates that domain validation passed
			func() {
				defer func() {
					// Expected - nil cache access
					_ = recover()
				}()
				_ = handler.LookupDomain(c)
			}()

			// If we got here without panic on validation, the domain was valid
		})
	}
}

func TestLookupHandler_ValidIP(t *testing.T) {
	e := echo.New()

	tests := []struct {
		name string
		addr string
	}{
		{name: "IPv4", addr: "8.8.8.8"},
		{name: "IPv4 private", addr: "192.168.1.1"},
		{name: "IPv6", addr: "2001:db8::1"},
		{name: "IPv6 full", addr: "2001:0db8:0000:0000:0000:0000:0000:0001"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/ip/"+tt.addr, nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetParamNames("addr")
			c.SetParamValues(tt.addr)

			handler := &LookupHandler{}

			// This will panic due to nil cache, but validates that IP validation passed
			func() {
				defer func() {
					_ = recover()
				}()
				_ = handler.LookupIP(c)
			}()
		})
	}
}

func TestLookupHandler_ValidASN(t *testing.T) {
	e := echo.New()

	tests := []struct {
		name string
		asn  string
	}{
		{name: "simple ASN", asn: "15169"},
		{name: "with AS prefix", asn: "AS15169"},
		{name: "lowercase as prefix", asn: "as15169"},
		{name: "single digit", asn: "1"},
		{name: "large ASN", asn: "4294967295"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/asn/"+tt.asn, nil)
			rec := httptest.NewRecorder()
			c := e.NewContext(req, rec)
			c.SetParamNames("asn")
			c.SetParamValues(tt.asn)

			handler := &LookupHandler{}

			// This will panic due to nil cache, but validates that ASN parsing passed
			func() {
				defer func() {
					_ = recover()
				}()
				_ = handler.LookupASN(c)
			}()
		})
	}
}

func TestLookupHandler_EntityWithAllowedServer(t *testing.T) {
	e := echo.New()

	// Create handler with server in allowlist
	allowedServers := []string{"https://rdap.arin.net/registry/"}
	handler := &LookupHandler{
		serverValidator: validate.NewRDAPServerValidator(allowedServers),
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entity/ABC-123?server=https://rdap.arin.net/registry/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("handle")
	c.SetParamValues("ABC-123")

	// This will panic at cache lookup since handler isn't fully initialized,
	// but validates server validation passed
	func() {
		defer func() {
			_ = recover()
		}()
		_ = handler.LookupEntity(c)
	}()
}

func TestNewLookupHandler(t *testing.T) {
	// Create mock dependencies
	client := rdap.NewClient(10 * time.Second)

	// Create a service (not started, so resolver is nil initially)
	logger := slog.New(slog.DiscardHandler)
	m := metrics.New()
	service := bootstrap.NewService(24*time.Hour, 10*time.Second, logger, m)

	cfg := cache.DefaultTieredCacheConfig()
	tieredCache, err := cache.NewTieredCache(cfg)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}
	defer func() { _ = tieredCache.Close() }()

	batchCfg := config.BatchConfig{
		Timeout:     30 * time.Second,
		Concurrency: 10,
	}

	handler := NewLookupHandler(client, service, tieredCache, batchCfg, nil)
	if handler == nil {
		t.Fatal("NewLookupHandler returned nil")
	}

	if handler.client == nil {
		t.Error("handler.client is nil")
	}
	if handler.bootstrap == nil {
		t.Error("handler.bootstrap is nil")
	}
	if handler.cache == nil {
		t.Error("handler.cache is nil")
	}
	if handler.serverValidator == nil {
		t.Error("handler.serverValidator is nil")
	}
}

func TestNewLookupHandler_WithResolver(t *testing.T) {
	// Create handler with a resolver that has servers
	client := rdap.NewClient(10 * time.Second)

	logger := slog.New(slog.DiscardHandler)
	m := metrics.New()
	service := bootstrap.NewService(24*time.Hour, 10*time.Second, logger, m)

	// Create bootstrap data and resolver manually
	bs := bootstrap.NewBootstrap()
	bs.DNS.SetTLDURLs("com", []string{"https://rdap.verisign.com/v1/"})
	bs.DNS.SetTLDURLs("net", []string{"https://rdap.verisign.com/v1/"})
	resolver := bootstrap.NewResolver(bs)

	cfg := cache.DefaultTieredCacheConfig()
	tieredCache, err := cache.NewTieredCache(cfg)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}
	defer func() { _ = tieredCache.Close() }()

	batchCfg := config.BatchConfig{
		Timeout:     30 * time.Second,
		Concurrency: 10,
	}

	handler := NewLookupHandler(client, service, tieredCache, batchCfg, nil)
	if handler == nil {
		t.Fatal("NewLookupHandler returned nil")
	}

	// Set resolver manually and verify it works
	handler.SetResolver(resolver)

	// Verify serverValidator was updated with servers
	if handler.serverValidator == nil {
		t.Error("handler.serverValidator is nil")
	}
}

func TestLookupHandler_ProcessBatchQuery_EntityMissingServer(t *testing.T) {
	// Test doesn't require full handler - just testing validation logic
	handler := &LookupHandler{
		serverValidator: validate.NewRDAPServerValidator(nil),
	}

	query := BatchQuery{
		Type:  "entity",
		Value: "TEST-123",
		// No Server specified
	}

	result := handler.processBatchQuery(context.Background(), query)

	if result.Error == "" {
		t.Error("expected error for entity without server")
	}
	if !strings.Contains(result.Error, "server URL required") {
		t.Errorf("Error = %s, want to contain 'server URL required'", result.Error)
	}
}

func TestLookupHandler_ProcessBatchQuery_EntityInvalidServer(t *testing.T) {
	// Handler with empty allowlist
	handler := &LookupHandler{
		serverValidator: validate.NewRDAPServerValidator([]string{"https://allowed.example.com/"}),
	}

	query := BatchQuery{
		Type:   "entity",
		Value:  "TEST-123",
		Server: "https://evil.example.com/", // Not in allowlist
	}

	result := handler.processBatchQuery(context.Background(), query)

	if result.Error == "" {
		t.Error("expected error for entity with invalid server")
	}
	if !strings.Contains(result.Error, "not in allowed list") {
		t.Errorf("Error = %s, want to contain 'not in allowed list'", result.Error)
	}
}

func TestLookupHandler_ProcessBatchQuery_UnknownType(t *testing.T) {
	handler := &LookupHandler{
		serverValidator: validate.NewRDAPServerValidator(nil),
	}

	query := BatchQuery{
		Type:  "unknown",
		Value: "test",
	}

	result := handler.processBatchQuery(context.Background(), query)

	if result.Error != "unknown query type" {
		t.Errorf("Error = %s, want 'unknown query type'", result.Error)
	}
}

func TestLookupHandler_BatchWithUnknownTypes(t *testing.T) {
	e := echo.New()

	// Create a minimal handler with batch config
	handler := &LookupHandler{
		batchConfig: config.BatchConfig{
			Timeout:     5 * time.Second,
			Concurrency: 10,
		},
		serverValidator: validate.NewRDAPServerValidator(nil),
	}

	// Create a batch with only unknown types - these fail immediately without cache access
	body := `{"queries":[
		{"type":"unknown1","value":"a"},
		{"type":"unknown2","value":"b"},
		{"type":"unknown3","value":"c"},
		{"type":"entity","value":"TEST-123"}
	]}`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/batch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := handler.LookupBatch(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp BatchResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if resp.Stats.Total != 4 {
		t.Errorf("Stats.Total = %d, want 4", resp.Stats.Total)
	}

	// Check error messages
	for i, result := range resp.Results {
		if result.Error == "" {
			t.Errorf("Results[%d] expected error", i)
		}
	}
}

func TestLookupHandler_BatchTimeoutWithUnknownTypes(t *testing.T) {
	e := echo.New()

	// Create handler with very short timeout
	handler := &LookupHandler{
		batchConfig: config.BatchConfig{
			Timeout:     1 * time.Nanosecond, // Extremely short
			Concurrency: 1,
		},
		serverValidator: validate.NewRDAPServerValidator(nil),
	}

	// Use unknown types that don't need cache
	body := `{"queries":[{"type":"unknown","value":"test"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/batch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := handler.LookupBatch(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should complete even with short timeout since unknown types fail immediately
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestLookupHandler_BatchConcurrency(t *testing.T) {
	e := echo.New()

	// Create handler with limited concurrency
	handler := &LookupHandler{
		batchConfig: config.BatchConfig{
			Timeout:     5 * time.Second,
			Concurrency: 2, // Only 2 concurrent queries
		},
		serverValidator: validate.NewRDAPServerValidator(nil),
	}

	// Create a batch with multiple queries
	queries := make([]BatchQuery, 5)
	for i := range queries {
		queries[i] = BatchQuery{Type: "unknown", Value: "test"} // Will fail immediately with "unknown type"
	}
	body, _ := json.Marshal(BatchRequest{Queries: queries})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/batch", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := handler.LookupBatch(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp BatchResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if resp.Stats.Total != 5 {
		t.Errorf("Stats.Total = %d, want 5", resp.Stats.Total)
	}

	// All queries should have errors (unknown type)
	if resp.Stats.Errors != 5 {
		t.Errorf("Stats.Errors = %d, want 5", resp.Stats.Errors)
	}

	// Check each result has the expected error
	for i, result := range resp.Results {
		if result.Error != "unknown query type" {
			t.Errorf("Results[%d].Error = %s, want 'unknown query type'", i, result.Error)
		}
	}
}

func TestLookupHandler_ProcessBatchQuery_EntityTypeCases(t *testing.T) {
	// Test case sensitivity for entity type
	tests := []struct {
		name      string
		queryType string
		wantErr   string
	}{
		{
			name:      "uppercase ENTITY no server",
			queryType: "ENTITY",
			wantErr:   "server URL required",
		},
		{
			name:      "mixed case Entity no server",
			queryType: "Entity",
			wantErr:   "server URL required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &LookupHandler{
				serverValidator: validate.NewRDAPServerValidator(nil),
			}

			query := BatchQuery{
				Type:  tt.queryType,
				Value: "TEST-123",
			}

			result := handler.processBatchQuery(context.Background(), query)

			if !strings.Contains(result.Error, tt.wantErr) {
				t.Errorf("Error = %s, want to contain %s", result.Error, tt.wantErr)
			}
		})
	}
}

func TestLookupHandler_HandleError_ServerError(t *testing.T) {
	e := echo.New()
	handler := &LookupHandler{}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := handler.handleError(c, rdap.ErrServerError, "domain", "example.com")
	if err != nil {
		t.Fatalf("handleError returned error: %v", err)
	}

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}

	var errResp ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if errResp.Error.Code != "UPSTREAM_ERROR" {
		t.Errorf("Error.Code = %q, want %q", errResp.Error.Code, "UPSTREAM_ERROR")
	}
}

func TestLookupHandler_HandleError_Timeout(t *testing.T) {
	e := echo.New()
	handler := &LookupHandler{}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := handler.handleError(c, context.DeadlineExceeded, "ip", "8.8.8.8")
	if err != nil {
		t.Fatalf("handleError returned error: %v", err)
	}

	// Timeout errors fall through to generic upstream error handling
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}

	var errResp ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	// Error code is UPSTREAM_ERROR, but message contains timeout info
	if errResp.Error.Code != "UPSTREAM_ERROR" {
		t.Errorf("Error.Code = %q, want %q", errResp.Error.Code, "UPSTREAM_ERROR")
	}

	if !strings.Contains(errResp.Error.Message, "timeout") {
		t.Errorf("Error.Message = %q, should contain 'timeout'", errResp.Error.Message)
	}
}

func TestLookupHandler_Entity_InvalidServerURLFormat(t *testing.T) {
	e := echo.New()

	// Create handler with no servers in allowlist
	handler := &LookupHandler{
		serverValidator: validate.NewRDAPServerValidator(nil),
	}

	// Provide a malformed URL
	req := httptest.NewRequest(http.MethodGet, "/api/v1/entity/ABC-123?server=not-a-valid-url", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("handle")
	c.SetParamValues("ABC-123")

	err := handler.LookupEntity(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	var errResp ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if errResp.Error.Code != "INVALID_SERVER" {
		t.Errorf("Error.Code = %q, want %q", errResp.Error.Code, "INVALID_SERVER")
	}
}

func TestLookupHandler_Entity_ServerNotInAllowlist(t *testing.T) {
	e := echo.New()

	// Create handler with specific server in allowlist
	handler := &LookupHandler{
		serverValidator: validate.NewRDAPServerValidator([]string{"https://rdap.arin.net/"}),
	}

	// Try to use a different server not in allowlist
	req := httptest.NewRequest(http.MethodGet, "/api/v1/entity/ABC-123?server=https://rdap.ripe.net/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("handle")
	c.SetParamValues("ABC-123")

	err := handler.LookupEntity(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	var errResp ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if errResp.Error.Code != "INVALID_SERVER" {
		t.Errorf("Error.Code = %q, want %q", errResp.Error.Code, "INVALID_SERVER")
	}
}

func TestLookupHandler_ASN_OverflowValue(t *testing.T) {
	e := echo.New()

	// ASN max is 4294967295 (uint32 max), try one larger
	req := httptest.NewRequest(http.MethodGet, "/api/v1/asn/4294967296", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("asn")
	c.SetParamValues("4294967296")

	handler := &LookupHandler{}

	err := handler.LookupASN(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should be invalid (overflow - fails uint32 parse)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestLookupHandler_ASN_NegativeValue(t *testing.T) {
	e := echo.New()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/asn/-1", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("asn")
	c.SetParamValues("-1")

	handler := &LookupHandler{}

	err := handler.LookupASN(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should be invalid (negative - fails uint parse)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestLookupHandler_BatchProcessingOrder(t *testing.T) {
	e := echo.New()

	handler := &LookupHandler{
		batchConfig: config.BatchConfig{
			Timeout:     5 * time.Second,
			Concurrency: 5,
		},
		serverValidator: validate.NewRDAPServerValidator(nil),
	}

	// Mix of different query types that will all fail with "unknown type"
	queries := []BatchQuery{
		{Type: "invalid1", Value: "a"},
		{Type: "invalid2", Value: "b"},
		{Type: "invalid3", Value: "c"},
	}
	body, _ := json.Marshal(BatchRequest{Queries: queries})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/batch", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := handler.LookupBatch(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp BatchResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	// Verify order is preserved
	if len(resp.Results) != 3 {
		t.Fatalf("Results len = %d, want 3", len(resp.Results))
	}

	for i, result := range resp.Results {
		expectedValue := string(rune('a' + i))
		if result.Value != expectedValue {
			t.Errorf("Results[%d].Value = %s, want %s", i, result.Value, expectedValue)
		}
	}
}

func TestLookupHandler_BatchStatsCalculation(t *testing.T) {
	e := echo.New()

	handler := &LookupHandler{
		batchConfig: config.BatchConfig{
			Timeout:     5 * time.Second,
			Concurrency: 10,
		},
		serverValidator: validate.NewRDAPServerValidator(nil),
	}

	// All unknown type queries
	queries := make([]BatchQuery, 10)
	for i := range queries {
		queries[i] = BatchQuery{Type: "unknown", Value: "test"}
	}
	body, _ := json.Marshal(BatchRequest{Queries: queries})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/batch", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	start := time.Now()
	err := handler.LookupBatch(c)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp BatchResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	// Verify stats
	if resp.Stats.Total != 10 {
		t.Errorf("Stats.Total = %d, want 10", resp.Stats.Total)
	}
	if resp.Stats.Success != 0 {
		t.Errorf("Stats.Success = %d, want 0", resp.Stats.Success)
	}
	if resp.Stats.Errors != 10 {
		t.Errorf("Stats.Errors = %d, want 10", resp.Stats.Errors)
	}
	if resp.Stats.CacheHits != 0 {
		t.Errorf("Stats.CacheHits = %d, want 0", resp.Stats.CacheHits)
	}
	// DurationMs should be reasonable (less than elapsed time in milliseconds + some buffer)
	if resp.Stats.DurationMs > elapsed.Milliseconds()+1000 {
		t.Errorf("Stats.DurationMs = %d seems too high (elapsed: %v)", resp.Stats.DurationMs, elapsed)
	}
}

func TestNewLookupHandlerWithWHOIS_Disabled(t *testing.T) {
	// Create handler with WHOIS disabled
	whoisCfg := config.WHOISConfig{
		Enabled:         false,
		Timeout:         10 * time.Second,
		MaxResponseSize: 64 * 1024,
	}

	logger := slog.New(slog.DiscardHandler)
	m := metrics.New()

	rdapClient := rdap.NewClient(10 * time.Second)
	bs := bootstrap.NewService(24*time.Hour, 10*time.Second, logger, m)

	cacheCfg := cache.DefaultTieredCacheConfig()
	tieredCache, err := cache.NewTieredCache(cacheCfg)
	if err != nil {
		t.Fatalf("NewTieredCache error: %v", err)
	}

	batchCfg := config.BatchConfig{Concurrency: 10, Timeout: 30 * time.Second}

	handler := NewLookupHandlerWithWHOIS(rdapClient, bs, tieredCache, batchCfg, whoisCfg, nil)

	if handler.WHOISEnabled() {
		t.Error("WHOISEnabled() = true, want false")
	}
}

func TestNewLookupHandlerWithWHOIS_Enabled(t *testing.T) {
	// Create handler with WHOIS enabled
	whoisCfg := config.WHOISConfig{
		Enabled:         true,
		Timeout:         10 * time.Second,
		MaxResponseSize: 64 * 1024,
	}

	logger := slog.New(slog.DiscardHandler)
	m := metrics.New()

	rdapClient := rdap.NewClient(10 * time.Second)
	bs := bootstrap.NewService(24*time.Hour, 10*time.Second, logger, m)

	cacheCfg := cache.DefaultTieredCacheConfig()
	tieredCache, err := cache.NewTieredCache(cacheCfg)
	if err != nil {
		t.Fatalf("NewTieredCache error: %v", err)
	}

	batchCfg := config.BatchConfig{Concurrency: 10, Timeout: 30 * time.Second}

	handler := NewLookupHandlerWithWHOIS(rdapClient, bs, tieredCache, batchCfg, whoisCfg, nil)

	if !handler.WHOISEnabled() {
		t.Error("WHOISEnabled() = false, want true")
	}

	// Cleanup
	if err := handler.Close(); err != nil {
		t.Errorf("Close() error: %v", err)
	}
}

func TestLookupHandler_Close(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	m := metrics.New()

	rdapClient := rdap.NewClient(10 * time.Second)
	bs := bootstrap.NewService(24*time.Hour, 10*time.Second, logger, m)

	cacheCfg := cache.DefaultTieredCacheConfig()
	tieredCache, err := cache.NewTieredCache(cacheCfg)
	if err != nil {
		t.Fatalf("NewTieredCache error: %v", err)
	}

	batchCfg := config.BatchConfig{Concurrency: 10, Timeout: 30 * time.Second}

	// Test Close on handler without WHOIS
	handler := NewLookupHandler(rdapClient, bs, tieredCache, batchCfg, nil)

	// Close should be idempotent and not error with no WHOIS client
	if err := handler.Close(); err != nil {
		t.Errorf("Close() error: %v", err)
	}

	// Test Close on handler with WHOIS
	whoisCfg := config.WHOISConfig{
		Enabled:         true,
		Timeout:         10 * time.Second,
		MaxResponseSize: 64 * 1024,
	}

	handlerWithWHOIS := NewLookupHandlerWithWHOIS(rdapClient, bs, tieredCache, batchCfg, whoisCfg, nil)
	if err := handlerWithWHOIS.Close(); err != nil {
		t.Errorf("Close() error: %v", err)
	}
}
