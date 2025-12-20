package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/glimps-re/rdap-lookup/pkg/rdaplookup"
)

// ReportGenerator generates markdown reports.
type ReportGenerator struct{}

// Generate creates a markdown report from analysis results.
func (g *ReportGenerator) Generate(w io.Writer, report *AnalysisReport) error {
	data := g.prepareTemplateData(report)

	// Write report sections
	if err := g.writeHeader(w, data); err != nil {
		return err
	}
	if err := g.writeSummary(w, data); err != nil {
		return err
	}
	if err := g.writeLibraryInfo(w, data); err != nil {
		return err
	}
	if err := g.writeTimingAnalysis(w, data); err != nil {
		return err
	}
	if err := g.writeSuccessfulLookups(w, data); err != nil {
		return err
	}
	if err := g.writeFailedLookups(w, data); err != nil {
		return err
	}
	if err := g.writeDistributions(w, data); err != nil {
		return err
	}
	if err := g.writeIPResults(w, data); err != nil {
		return err
	}
	if err := g.writeRawData(w, data); err != nil {
		return err
	}

	return nil
}

func (g *ReportGenerator) writeHeader(w io.Writer, data *TemplateData) error {
	_, err := fmt.Fprintf(w, "# PhishStats Domain Analysis Report\n\nGenerated: %s\n\n",
		data.GeneratedAt.Format("2006-01-02T15:04:05Z"))
	return err
}

func (g *ReportGenerator) writeSummary(w io.Writer, data *TemplateData) error {
	_, err := fmt.Fprintf(w, `## Executive Summary

| Metric | Value |
|--------|-------|
| Phishing URLs fetched | %d |
| Unique domains | %d |
| Successful lookups | %d |
| Failed lookups | %d |
| Cache hits | %d |
| Total duration | %s |
| Average lookup time | %s |

`, data.PhishingURLCount, data.UniqueDomainCount, data.SuccessCount,
		data.ErrorCount, data.CacheHits, data.TotalDuration, data.AvgLookupTime)
	return err
}

func (g *ReportGenerator) writeLibraryInfo(w io.Writer, data *TemplateData) error {
	_, err := fmt.Fprintf(w, "## Library Information\n\n| Property | Value |\n|----------|-------|\n")
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(w, "| Client Mode | %s |\n", data.ClientMode)
	if err != nil {
		return err
	}

	if data.ServerURL != "" {
		_, err = fmt.Fprintf(w, "| Server URL | %s |\n", data.ServerURL)
		if err != nil {
			return err
		}
	}

	if data.ClientMode == "standalone" {
		_, err = fmt.Fprintf(w, "| Cache Enabled | %t |\n", data.CacheEnabled)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(w, "| Cache Size | %dMB |\n", data.CacheSizeMB)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(w, "| Cache TTL | %s |\n", data.CacheTTL)
		if err != nil {
			return err
		}
	}

	_, err = fmt.Fprintf(w, "| Init Time | %s |\n\n", data.BootstrapDuration)
	return err
}

func (g *ReportGenerator) writeTimingAnalysis(w io.Writer, data *TemplateData) error {
	_, err := fmt.Fprintf(w, `## Timing Analysis

### Lookup Performance

| Percentile | Time |
|------------|------|
| P50 | %s |
| P95 | %s |
| P99 | %s |
| Max | %s |
| Min | %s |

### By TLD

| TLD | Count | Avg Time | Success Rate |
|-----|-------|----------|--------------|
`, data.P50, data.P95, data.P99, data.MaxTime, data.MinTime)
	if err != nil {
		return err
	}

	for _, tld := range data.TLDStats {
		_, err = fmt.Fprintf(w, "| .%s | %d | %s | %d%% |\n",
			tld.TLD, tld.Count, tld.AvgTime, tld.SuccessRate)
		if err != nil {
			return err
		}
	}
	_, err = fmt.Fprintln(w)
	return err
}

func (g *ReportGenerator) writeSuccessfulLookups(w io.Writer, data *TemplateData) error {
	_, err := fmt.Fprintln(w, "## Successful Lookups")
	if err != nil {
		return err
	}

	for _, r := range data.SuccessfulResults {
		_, err = fmt.Fprintf(w, `
### %s

| Property | Value |
|----------|-------|
| Registrar | %s |
| Created | %s |
| Expires | %s |
| Country | %s |
| DNSSEC | %t |
| Nameservers | %s |
| Lookup Time | %s |
| Cached | %t |
| RDAP Server | %s |
| Source URL | %s |

`, r.Domain, r.Registrar, r.Created, r.Expires, r.Country,
			r.DNSSEC, r.Nameservers, r.Duration, r.Cached, r.RDAPServer, r.SourceURL)
		if err != nil {
			return err
		}
	}
	return nil
}

func (g *ReportGenerator) writeFailedLookups(w io.Writer, data *TemplateData) error {
	if len(data.FailedResults) == 0 {
		return nil
	}

	_, err := fmt.Fprintln(w, "## Failed Lookups")
	if err != nil {
		return err
	}

	// Error summary
	_, err = fmt.Fprintln(w, `
### Error Summary

| Error Type | Count | Examples |
|------------|-------|----------|`)
	if err != nil {
		return err
	}

	for _, e := range data.ErrorSummary {
		_, err = fmt.Fprintf(w, "| %s | %d | %s |\n", e.Type, e.Count, e.Examples)
		if err != nil {
			return err
		}
	}

	_, err = fmt.Fprintln(w, "\n### Detailed Errors")
	if err != nil {
		return err
	}

	for _, r := range data.FailedResults {
		_, err = fmt.Fprintf(w, `
#### %s

- **Error**: %s
- **Source URL**: %s
- **Duration**: %s

`, r.Domain, r.Error, r.SourceURL, r.Duration)
		if err != nil {
			return err
		}
	}
	return nil
}

func (g *ReportGenerator) writeDistributions(w io.Writer, data *TemplateData) error {
	// TLD distribution
	_, err := fmt.Fprintln(w, `## TLD Distribution

| TLD | Count | Percentage |
|-----|-------|------------|`)
	if err != nil {
		return err
	}

	for _, d := range data.TLDDistribution {
		_, err = fmt.Fprintf(w, "| .%s | %d | %.1f%% |\n", d.TLD, d.Count, d.Percentage)
		if err != nil {
			return err
		}
	}

	// Country distribution
	_, err = fmt.Fprintln(w, `
## Country Distribution

| Country | Count | Percentage |
|---------|-------|------------|`)
	if err != nil {
		return err
	}

	for _, d := range data.CountryDistribution {
		_, err = fmt.Fprintf(w, "| %s | %d | %.1f%% |\n", d.Country, d.Count, d.Percentage)
		if err != nil {
			return err
		}
	}
	_, err = fmt.Fprintln(w)
	return err
}

func (g *ReportGenerator) writeIPResults(w io.Writer, data *TemplateData) error {
	if len(data.IPResults) == 0 {
		return nil
	}

	_, err := fmt.Fprintln(w, `## IP Analysis

| IP | Domain | RIR | Country | CIDR |
|----|--------|-----|---------|------|`)
	if err != nil {
		return err
	}

	for _, r := range data.IPResults {
		_, err = fmt.Fprintf(w, "| %s | %s | %s | %s | %s |\n",
			r.IP, r.Domain, r.RIR, r.Country, r.CIDR)
		if err != nil {
			return err
		}
	}
	_, err = fmt.Fprintln(w)
	return err
}

func (g *ReportGenerator) writeRawData(w io.Writer, data *TemplateData) error {
	// All timings
	_, err := fmt.Fprintln(w, `## Raw Data

<details>
<summary>All Lookup Timings (click to expand)</summary>

| Domain | Time (ms) | Status | Cached |
|--------|-----------|--------|--------|`)
	if err != nil {
		return err
	}

	for _, t := range data.AllTimings {
		_, err = fmt.Fprintf(w, "| %s | %d | %s | %t |\n",
			t.Domain, t.DurationMs, t.Status, t.Cached)
		if err != nil {
			return err
		}
	}

	_, err = fmt.Fprintln(w, `
</details>

<details>
<summary>PhishStats Entries (click to expand)</summary>

| URL | TLD | Score | Date |
|-----|-----|-------|------|`)
	if err != nil {
		return err
	}

	for _, e := range data.PhishEntries {
		_, err = fmt.Fprintf(w, "| %s | %s | %.1f | %s |\n",
			e.URL, e.TLD, e.Score, e.Date)
		if err != nil {
			return err
		}
	}

	_, err = fmt.Fprintln(w, "\n</details>")
	return err
}

// TemplateData holds all data for the report.
type TemplateData struct {
	// From report
	GeneratedAt       time.Time
	PhishingURLCount  int
	UniqueDomainCount int
	BootstrapDuration string
	TotalDuration     string
	CacheEnabled      bool
	CacheSizeMB       int64
	CacheTTL          string

	// Client mode
	ClientMode string
	ServerURL  string

	// Calculated
	SuccessCount  int
	ErrorCount    int
	CacheHits     int
	AvgLookupTime string
	P50           string
	P95           string
	P99           string
	MaxTime       string
	MinTime       string

	// Grouped data
	TLDStats            []TLDStat
	TLDDistribution     []Distribution
	CountryDistribution []Distribution
	SuccessfulResults   []SuccessResult
	FailedResults       []FailedResult
	ErrorSummary        []ErrorSummaryItem
	AllTimings          []TimingEntry
	PhishEntries        []PhishEntry
	IPResults           []IPResult
}

// TLDStat holds statistics for a TLD.
type TLDStat struct {
	TLD         string
	Count       int
	AvgTime     string
	SuccessRate int
}

// Distribution holds distribution data for TLD or country.
type Distribution struct {
	TLD        string
	Country    string
	Count      int
	Percentage float64
}

// SuccessResult holds a successful lookup result for display.
type SuccessResult struct {
	Domain      string
	Registrar   string
	Created     string
	Expires     string
	Country     string
	DNSSEC      bool
	Nameservers string
	Duration    string
	Cached      bool
	RDAPServer  string
	SourceURL   string
}

// FailedResult holds a failed lookup result for display.
type FailedResult struct {
	Domain    string
	Error     string
	SourceURL string
	Duration  string
}

// ErrorSummaryItem holds error summary data.
type ErrorSummaryItem struct {
	Type     string
	Count    int
	Examples string
}

// TimingEntry holds timing data for a lookup.
type TimingEntry struct {
	Domain     string
	DurationMs int64
	Status     string
	Cached     bool
}

// PhishEntry holds phishing entry data for display.
type PhishEntry struct {
	URL   string
	TLD   string
	Score float64
	Date  string
}

// IPResult holds IP lookup result for display.
type IPResult struct {
	IP      string
	Domain  string
	RIR     string
	Country string
	CIDR    string
}

func (g *ReportGenerator) prepareTemplateData(report *AnalysisReport) *TemplateData {
	data := &TemplateData{
		GeneratedAt:       report.GeneratedAt,
		PhishingURLCount:  report.PhishingURLCount,
		UniqueDomainCount: report.UniqueDomainCount,
		BootstrapDuration: report.BootstrapDuration.Round(time.Millisecond).String(),
		TotalDuration:     report.TotalDuration.Round(time.Millisecond).String(),
		CacheEnabled:      report.CacheEnabled,
		CacheSizeMB:       report.CacheSize / (1024 * 1024),
		CacheTTL:          report.CacheTTL.String(),
		ClientMode:        string(report.ClientMode),
		ServerURL:         report.ServerURL,
	}

	// Process domain results
	var durations []time.Duration
	tldCounts := make(map[string]int)
	tldSuccess := make(map[string]int)
	tldTimes := make(map[string][]time.Duration)
	countryCounts := make(map[string]int)
	errorCounts := make(map[string][]string)

	for _, r := range report.DomainResults {
		durations = append(durations, r.Duration)

		// Extract TLD
		parts := strings.Split(r.Domain, ".")
		tld := parts[len(parts)-1]
		tldCounts[tld]++
		tldTimes[tld] = append(tldTimes[tld], r.Duration)

		// Add timing entry
		status := "OK"
		if r.Error != nil {
			status = classifyError(r.Error)
			errorCounts[status] = append(errorCounts[status], r.Domain)
			data.ErrorCount++

			data.FailedResults = append(data.FailedResults, FailedResult{
				Domain:    r.Domain,
				Error:     r.Error.Error(),
				SourceURL: truncateURL(r.SourceURL, 60),
				Duration:  r.Duration.Round(time.Millisecond).String(),
			})
		} else {
			data.SuccessCount++
			tldSuccess[tld]++

			if r.Response != nil {
				country := r.Response.Country
				if country == "" {
					country = "Unknown"
				}
				countryCounts[country]++

				data.SuccessfulResults = append(data.SuccessfulResults, SuccessResult{
					Domain:      r.Domain,
					Registrar:   getRegistrarName(r.Response),
					Created:     formatDate(r.Response.CreatedDate),
					Expires:     formatDate(r.Response.ExpirationDate),
					Country:     country,
					DNSSEC:      getDNSSECSigned(r.Response.DNSSEC),
					Nameservers: formatNameservers(r.Response.Nameservers),
					Duration:    r.Duration.Round(time.Millisecond).String(),
					Cached:      r.Cached,
					RDAPServer:  r.Response.RDAPServer,
					SourceURL:   truncateURL(r.SourceURL, 60),
				})
			}
		}

		if r.Cached {
			data.CacheHits++
		}

		data.AllTimings = append(data.AllTimings, TimingEntry{
			Domain:     r.Domain,
			DurationMs: r.Duration.Milliseconds(),
			Status:     status,
			Cached:     r.Cached,
		})
	}

	// Calculate percentiles
	if len(durations) > 0 {
		sort.Slice(durations, func(i, j int) bool {
			return durations[i] < durations[j]
		})

		data.P50 = percentile(durations, 50)
		data.P95 = percentile(durations, 95)
		data.P99 = percentile(durations, 99)
		data.MinTime = durations[0].Round(time.Millisecond).String()
		data.MaxTime = durations[len(durations)-1].Round(time.Millisecond).String()

		var total time.Duration
		for _, d := range durations {
			total += d
		}
		avg := total / time.Duration(len(durations))
		data.AvgLookupTime = avg.Round(time.Millisecond).String()
	} else {
		data.P50, data.P95, data.P99 = "N/A", "N/A", "N/A"
		data.MinTime, data.MaxTime, data.AvgLookupTime = "N/A", "N/A", "N/A"
	}

	// TLD stats
	for tld, count := range tldCounts {
		times := tldTimes[tld]
		var total time.Duration
		for _, t := range times {
			total += t
		}
		avg := total / time.Duration(len(times))

		successRate := 0
		if count > 0 {
			successRate = (tldSuccess[tld] * 100) / count
		}

		data.TLDStats = append(data.TLDStats, TLDStat{
			TLD:         tld,
			Count:       count,
			AvgTime:     avg.Round(time.Millisecond).String(),
			SuccessRate: successRate,
		})
	}
	sort.Slice(data.TLDStats, func(i, j int) bool {
		return data.TLDStats[i].Count > data.TLDStats[j].Count
	})

	// TLD distribution
	totalDomains := len(report.DomainResults)
	for tld, count := range tldCounts {
		pct := 0.0
		if totalDomains > 0 {
			pct = float64(count) * 100 / float64(totalDomains)
		}
		data.TLDDistribution = append(data.TLDDistribution, Distribution{
			TLD:        tld,
			Count:      count,
			Percentage: pct,
		})
	}
	sort.Slice(data.TLDDistribution, func(i, j int) bool {
		return data.TLDDistribution[i].Count > data.TLDDistribution[j].Count
	})

	// Country distribution
	for country, count := range countryCounts {
		pct := 0.0
		if data.SuccessCount > 0 {
			pct = float64(count) * 100 / float64(data.SuccessCount)
		}
		data.CountryDistribution = append(data.CountryDistribution, Distribution{
			Country:    country,
			Count:      count,
			Percentage: pct,
		})
	}
	sort.Slice(data.CountryDistribution, func(i, j int) bool {
		return data.CountryDistribution[i].Count > data.CountryDistribution[j].Count
	})

	// Error summary
	for errType, domains := range errorCounts {
		maxExamples := 3
		if len(domains) < maxExamples {
			maxExamples = len(domains)
		}
		examples := strings.Join(domains[:maxExamples], ", ")
		if len(domains) > 3 {
			examples += "..."
		}
		data.ErrorSummary = append(data.ErrorSummary, ErrorSummaryItem{
			Type:     errType,
			Count:    len(domains),
			Examples: examples,
		})
	}
	sort.Slice(data.ErrorSummary, func(i, j int) bool {
		return data.ErrorSummary[i].Count > data.ErrorSummary[j].Count
	})

	// Phish entries
	for _, e := range report.PhishingEntries {
		data.PhishEntries = append(data.PhishEntries, PhishEntry{
			URL:   truncateURL(e.URL, 80),
			TLD:   e.TLD,
			Score: e.Score,
			Date:  e.Date,
		})
	}

	// IP results
	for _, r := range report.IPResults {
		if r.Error == nil && r.Response != nil {
			data.IPResults = append(data.IPResults, IPResult{
				IP:      r.IP,
				Domain:  r.Domain,
				RIR:     extractRIR(r.Response.RDAPServer),
				Country: r.Response.Country,
				CIDR:    formatCIDRList(r.Response.CIDR),
			})
		}
	}

	return data
}

// Helper functions
func percentile(durations []time.Duration, p int) string {
	if len(durations) == 0 {
		return "N/A"
	}
	idx := (len(durations) * p) / 100
	if idx >= len(durations) {
		idx = len(durations) - 1
	}
	return durations[idx].Round(time.Millisecond).String()
}

func classifyError(err error) string {
	errStr := err.Error()
	switch {
	case strings.Contains(errStr, "not found"):
		return "NOT_FOUND"
	case strings.Contains(errStr, "timeout"):
		return "TIMEOUT"
	case strings.Contains(errStr, "rate limit"):
		return "RATE_LIMITED"
	case strings.Contains(errStr, "no RDAP server"):
		return "NO_SERVER"
	default:
		return "OTHER"
	}
}

func getRegistrarName(r *rdaplookup.DomainResponse) string {
	if r.Registrar != nil && r.Registrar.Name != "" {
		return r.Registrar.Name
	}
	return "Unknown"
}

func getDNSSECSigned(dnssec *rdaplookup.SimpleDNSSEC) bool {
	if dnssec == nil {
		return false
	}
	return dnssec.Signed || dnssec.DelegationSigned
}

func formatCIDRList(cidrs []string) string {
	if len(cidrs) == 0 {
		return "N/A"
	}
	return strings.Join(cidrs, ", ")
}

func formatDate(date string) string {
	if date == "" {
		return "N/A"
	}
	// Try to parse and format nicely
	t, err := time.Parse(time.RFC3339, date)
	if err != nil {
		return date
	}
	return t.Format("2006-01-02")
}

func formatNameservers(ns []rdaplookup.SimpleNS) string {
	if len(ns) == 0 {
		return "N/A"
	}
	names := make([]string, 0, len(ns))
	for _, n := range ns {
		names = append(names, n.Name)
	}
	if len(names) > 3 {
		return strings.Join(names[:3], ", ") + "..."
	}
	return strings.Join(names, ", ")
}

func truncateURL(urlStr string, maxLen int) string {
	if len(urlStr) <= maxLen {
		return urlStr
	}
	return urlStr[:maxLen-3] + "..."
}

func extractRIR(server string) string {
	switch {
	case strings.Contains(server, "arin"):
		return "ARIN"
	case strings.Contains(server, "ripe"):
		return "RIPE"
	case strings.Contains(server, "apnic"):
		return "APNIC"
	case strings.Contains(server, "lacnic"):
		return "LACNIC"
	case strings.Contains(server, "afrinic"):
		return "AFRINIC"
	default:
		return "Unknown"
	}
}
