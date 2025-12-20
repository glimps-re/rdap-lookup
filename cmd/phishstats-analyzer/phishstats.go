// Package main provides a debug tool to analyze phishing domains using RDAP.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	phishStatsAPIURL = "https://api.phishstats.info/api/phishing"
	maxResponseSize  = 10 * 1024 * 1024 // 10MB
)

// PhishingEntry represents a single phishing record from PhishStats API.
type PhishingEntry struct {
	ID          int64   `json:"id"`
	URL         string  `json:"url"`
	IP          string  `json:"ip"`
	CountryCode string  `json:"countrycode"`
	ASN         string  `json:"asn"`
	TLD         string  `json:"tld"`
	Date        string  `json:"date"`
	Title       string  `json:"title"`
	Score       float64 `json:"score"`
}

// PhishStatsClient fetches data from PhishStats API.
type PhishStatsClient struct {
	httpClient *http.Client
	userAgent  string
}

// NewPhishStatsClient creates a new PhishStats API client.
func NewPhishStatsClient() *PhishStatsClient {
	return &PhishStatsClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		userAgent:  "rdap-lookup-debug-tool/1.0",
	}
}

// FetchPhishingURLs retrieves recent phishing URLs from PhishStats.
func (c *PhishStatsClient) FetchPhishingURLs(ctx context.Context, count int) ([]PhishingEntry, error) {
	// Clamp count to API maximum
	if count > 100 {
		count = 100
	}
	if count < 1 {
		count = 1
	}

	// Build URL with parameters
	params := url.Values{}
	params.Set("_size", fmt.Sprintf("%d", count))
	params.Set("_sort", "-date")

	reqURL := fmt.Sprintf("%s?%s", phishStatsAPIURL, params.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch phishing data: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	// Read with size limit
	limited := io.LimitReader(resp.Body, maxResponseSize)
	var entries []PhishingEntry
	if err := json.NewDecoder(limited).Decode(&entries); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return entries, nil
}
