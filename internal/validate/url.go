// Package validate provides input validation for security-sensitive data.
package validate

import (
	"errors"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Common validation errors.
var (
	ErrEmptyURL         = errors.New("server URL is empty")
	ErrInvalidURL       = errors.New("invalid server URL format")
	ErrServerNotAllowed = errors.New("server URL not in allowed list")
)

// RDAPServerValidator validates server URLs against an allowlist
// populated from IANA bootstrap data.
type RDAPServerValidator struct {
	mu             sync.RWMutex
	allowedServers map[string]struct{} // normalized server hosts
	lastUpdated    time.Time           // time of last allowlist update
}

// NewRDAPServerValidator creates a validator with servers from bootstrap.
func NewRDAPServerValidator(bootstrapServers []string) *RDAPServerValidator {
	v := &RDAPServerValidator{
		allowedServers: make(map[string]struct{}),
	}
	v.UpdateAllowlist(bootstrapServers)
	return v
}

// IsAllowed checks if a server URL is in the allowlist.
// Returns nil if allowed, error otherwise.
func (v *RDAPServerValidator) IsAllowed(serverURL string) error {
	if serverURL == "" {
		return ErrEmptyURL
	}

	normalized, err := normalizeServerURL(serverURL)
	if err != nil {
		return err
	}

	v.mu.RLock()
	defer v.mu.RUnlock()

	if _, ok := v.allowedServers[normalized]; !ok {
		return ErrServerNotAllowed
	}

	return nil
}

// UpdateAllowlist replaces the current allowlist with servers from bootstrap.
// This should be called whenever bootstrap data is refreshed.
func (v *RDAPServerValidator) UpdateAllowlist(servers []string) {
	newAllowed := make(map[string]struct{}, len(servers))

	for _, server := range servers {
		normalized, err := normalizeServerURL(server)
		if err != nil {
			// Skip invalid URLs from bootstrap data
			continue
		}
		newAllowed[normalized] = struct{}{}
	}

	v.mu.Lock()
	v.allowedServers = newAllowed
	v.lastUpdated = time.Now()
	v.mu.Unlock()
}

// AllowedCount returns the number of allowed servers.
func (v *RDAPServerValidator) AllowedCount() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.allowedServers)
}

// LastUpdated returns the time of the last allowlist update.
func (v *RDAPServerValidator) LastUpdated() time.Time {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.lastUpdated
}

// StalenessAge returns how long since the last update.
// Returns 0 if the allowlist has never been updated.
func (v *RDAPServerValidator) StalenessAge() time.Duration {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.lastUpdated.IsZero() {
		return 0
	}
	return time.Since(v.lastUpdated)
}

// IsStale returns true if the allowlist is older than the given threshold.
func (v *RDAPServerValidator) IsStale(maxAge time.Duration) bool {
	age := v.StalenessAge()
	if age == 0 {
		return false // Never updated, not stale yet
	}
	return age > maxAge
}

// normalizeServerURL normalizes a server URL for consistent comparison.
// It extracts and normalizes the host portion of the URL.
func normalizeServerURL(serverURL string) (string, error) {
	if serverURL == "" {
		return "", ErrInvalidURL
	}

	// Ensure URL has a scheme for proper parsing
	urlToParse := serverURL
	if !strings.HasPrefix(urlToParse, "http://") && !strings.HasPrefix(urlToParse, "https://") {
		urlToParse = "https://" + urlToParse
	}

	parsed, err := url.Parse(urlToParse)
	if err != nil {
		return "", ErrInvalidURL
	}

	host := strings.ToLower(parsed.Host)
	if host == "" {
		return "", ErrInvalidURL
	}

	// Validate host format - must contain at least one dot for a valid domain
	// or be a valid IP address
	if !strings.Contains(host, ".") && !strings.Contains(host, ":") {
		return "", ErrInvalidURL
	}

	// Remove default port if present
	host = strings.TrimSuffix(host, ":443")
	host = strings.TrimSuffix(host, ":80")

	return host, nil
}
