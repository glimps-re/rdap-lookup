package api

import (
	"net/http"
	"os"
	"time"

	"github.com/labstack/echo/v4"
)

// BuildInfo holds version information passed from main.
type BuildInfo struct {
	Version   string
	GitCommit string
}

// MetaResponse represents the service metadata response.
type MetaResponse struct {
	Service   string `json:"service"`
	Version   string `json:"version"`
	GitCommit string `json:"git_commit"`
	Hostname  string `json:"hostname"`
	Uptime    string `json:"uptime"`
	StartTime string `json:"start_time"`
}

// MetaHandler provides the /meta endpoint.
type MetaHandler struct {
	buildInfo BuildInfo
	startTime time.Time
}

// NewMetaHandler creates a new MetaHandler with build information.
func NewMetaHandler(info BuildInfo) *MetaHandler {
	return &MetaHandler{
		buildInfo: info,
		startTime: time.Now(),
	}
}

// Handle handles the /meta endpoint.
func (h *MetaHandler) Handle(c echo.Context) error {
	uptime := time.Since(h.startTime)

	hostname, _ := os.Hostname()

	resp := MetaResponse{
		Service:   "rdap-lookup",
		Version:   h.buildInfo.Version,
		GitCommit: h.buildInfo.GitCommit,
		Hostname:  hostname,
		Uptime:    uptime.Round(time.Second).String(),
		StartTime: h.startTime.UTC().Format(time.RFC3339),
	}

	return c.JSON(http.StatusOK, resp)
}
