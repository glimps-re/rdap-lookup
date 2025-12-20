package validate

import (
	"errors"
	"net"
	"regexp"
	"strings"
	"unicode"
)

// Input validation errors.
var (
	ErrEmptyDomain       = errors.New("domain name is empty")
	ErrDomainTooLong     = errors.New("domain name exceeds 253 characters")
	ErrLabelTooLong      = errors.New("domain label exceeds 63 characters")
	ErrInvalidDomainChar = errors.New("domain contains invalid characters")
	ErrInvalidLabelStart = errors.New("domain label cannot start or end with hyphen")

	ErrEmptyIP   = errors.New("IP address is empty")
	ErrInvalidIP = errors.New("invalid IP address format")

	ErrInvalidASN    = errors.New("invalid ASN format")
	ErrASNOutOfRange = errors.New("ASN out of valid range (1-4294967295)")

	ErrEmptyHandle       = errors.New("entity handle is empty")
	ErrHandleTooLong     = errors.New("entity handle exceeds 256 characters")
	ErrInvalidHandleChar = errors.New("entity handle contains invalid characters")
)

// Maximum lengths for validation.
const (
	MaxDomainLength = 253
	MaxLabelLength  = 63
	MaxHandleLength = 256
	MaxASN          = 4294967295
)

// domainLabelRegex matches valid domain labels (RFC 1123).
// Labels must start with alphanumeric, can contain hyphens in the middle,
// and end with alphanumeric.
var domainLabelRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// ValidateDomain validates a domain name format per RFC 1035/1123.
// It checks:
// - Maximum 253 characters total
// - Maximum 63 characters per label
// - Valid characters (a-z, 0-9, hyphen)
// - Labels cannot start or end with hyphen
// - IDN (punycode) domains are supported
func ValidateDomain(name string) error {
	if name == "" {
		return ErrEmptyDomain
	}

	// Normalize to lowercase
	name = strings.ToLower(name)

	// Remove trailing dot if present
	name = strings.TrimSuffix(name, ".")

	// Check total length
	if len(name) > MaxDomainLength {
		return ErrDomainTooLong
	}

	// Split into labels and validate each
	labels := strings.Split(name, ".")
	if len(labels) == 0 {
		return ErrEmptyDomain
	}

	for _, label := range labels {
		if label == "" {
			return ErrInvalidDomainChar
		}

		if len(label) > MaxLabelLength {
			return ErrLabelTooLong
		}

		// Check for valid label format
		if !domainLabelRegex.MatchString(label) {
			// Check if it starts/ends with hyphen for a more specific error
			if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return ErrInvalidLabelStart
			}
			return ErrInvalidDomainChar
		}
	}

	return nil
}

// ValidateIP validates an IPv4 or IPv6 address format.
func ValidateIP(addr string) error {
	if addr == "" {
		return ErrEmptyIP
	}

	// Use net.ParseIP for validation
	ip := net.ParseIP(addr)
	if ip == nil {
		return ErrInvalidIP
	}

	return nil
}

// ValidateASN validates that an ASN is within valid range (1-4294967295).
// The asn parameter should already be parsed from string.
func ValidateASN(asn uint64) error {
	if asn == 0 {
		return ErrASNOutOfRange
	}
	if asn > MaxASN {
		return ErrASNOutOfRange
	}
	return nil
}

// ValidateEntityHandle validates an entity handle format.
// It checks:
// - Non-empty
// - Maximum 256 characters
// - No control characters
// - No problematic Unicode categories (format, private use, surrogates)
func ValidateEntityHandle(handle string) error {
	if handle == "" {
		return ErrEmptyHandle
	}

	if len(handle) > MaxHandleLength {
		return ErrHandleTooLong
	}

	// Check for invalid characters
	for _, r := range handle {
		// Block control characters
		if unicode.IsControl(r) {
			return ErrInvalidHandleChar
		}
		// Block problematic Unicode categories that could cause issues
		// Cf = Format characters (zero-width joiners, etc.)
		// Co = Private use characters
		// Cs = Surrogates (invalid in UTF-8)
		if unicode.Is(unicode.Cf, r) ||
			unicode.Is(unicode.Co, r) ||
			unicode.Is(unicode.Cs, r) {
			return ErrInvalidHandleChar
		}
	}

	return nil
}
