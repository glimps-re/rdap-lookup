package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
)

func TestMetaHandler_Handle(t *testing.T) {
	e := echo.New()
	buildInfo := BuildInfo{
		Version:   "1.0.0",
		GitCommit: "abc123",
	}
	handler := NewMetaHandler(buildInfo)

	req := httptest.NewRequest(http.MethodGet, "/meta", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := handler.Handle(c)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp MetaResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if resp.Service != "rdap-lookup" {
		t.Errorf("Service = %q, want %q", resp.Service, "rdap-lookup")
	}

	if resp.Version != "1.0.0" {
		t.Errorf("Version = %q, want %q", resp.Version, "1.0.0")
	}

	if resp.GitCommit != "abc123" {
		t.Errorf("GitCommit = %q, want %q", resp.GitCommit, "abc123")
	}

	if resp.StartTime == "" {
		t.Error("StartTime is empty")
	}

	if resp.Uptime == "" {
		t.Error("Uptime is empty")
	}
}

func TestMetaHandler_Uptime(t *testing.T) {
	buildInfo := BuildInfo{
		Version:   "dev",
		GitCommit: "unknown",
	}
	handler := NewMetaHandler(buildInfo)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/meta", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := handler.Handle(c)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	var resp MetaResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	// Uptime should be parseable as a duration
	_, err = time.ParseDuration(resp.Uptime)
	if err != nil {
		t.Errorf("Uptime %q is not a valid duration: %v", resp.Uptime, err)
	}
}

func TestBuildInfo_DefaultValues(t *testing.T) {
	// Test with empty build info
	buildInfo := BuildInfo{}
	handler := NewMetaHandler(buildInfo)

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/meta", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := handler.Handle(c)
	if err != nil {
		t.Fatalf("Handle error: %v", err)
	}

	var resp MetaResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	// Version should be empty string (passed from main)
	if resp.Version != "" {
		t.Errorf("Version = %q, want empty", resp.Version)
	}
}
