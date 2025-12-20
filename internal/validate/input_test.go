package validate

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateDomain(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		wantErr error
	}{
		// Valid domains
		{name: "simple domain", domain: "example.com", wantErr: nil},
		{name: "subdomain", domain: "sub.example.com", wantErr: nil},
		{name: "deep subdomain", domain: "a.b.c.example.com", wantErr: nil},
		{name: "with trailing dot", domain: "example.com.", wantErr: nil},
		{name: "numeric TLD", domain: "example.123", wantErr: nil},
		{name: "with hyphen", domain: "my-example.com", wantErr: nil},
		{name: "punycode IDN", domain: "xn--nxasmq5b.com", wantErr: nil},
		{name: "all numeric label", domain: "123.example.com", wantErr: nil},
		{name: "single char labels", domain: "a.b.c", wantErr: nil},
		{name: "uppercase normalized", domain: "EXAMPLE.COM", wantErr: nil},

		// Invalid domains
		{name: "empty string", domain: "", wantErr: ErrEmptyDomain},
		{name: "too long", domain: strings.Repeat("a", 254), wantErr: ErrDomainTooLong},
		{name: "label too long", domain: strings.Repeat("a", 64) + ".com", wantErr: ErrLabelTooLong},
		{name: "starts with hyphen", domain: "-example.com", wantErr: ErrInvalidLabelStart},
		{name: "ends with hyphen", domain: "example-.com", wantErr: ErrInvalidLabelStart},
		{name: "invalid char underscore", domain: "exam_ple.com", wantErr: ErrInvalidDomainChar},
		{name: "invalid char space", domain: "exam ple.com", wantErr: ErrInvalidDomainChar},
		{name: "double dot", domain: "example..com", wantErr: ErrInvalidDomainChar},
		{name: "leading dot", domain: ".example.com", wantErr: ErrInvalidDomainChar},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDomain(tt.domain)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidateDomain(%q) = %v, want %v", tt.domain, err, tt.wantErr)
			}
		})
	}
}

func TestValidateDomain_EdgeCases(t *testing.T) {
	// Test max length domain (253 chars)
	maxDomain := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	if len(maxDomain) != 253 {
		t.Fatalf("maxDomain length is %d, expected 253", len(maxDomain))
	}
	if err := ValidateDomain(maxDomain); err != nil {
		t.Errorf("ValidateDomain with 253 chars should be valid, got %v", err)
	}

	// Test one char over max
	tooLong := maxDomain + "a"
	if err := ValidateDomain(tooLong); !errors.Is(err, ErrDomainTooLong) {
		t.Errorf("ValidateDomain with 254 chars should return ErrDomainTooLong, got %v", err)
	}
}

func TestValidateIP(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr error
	}{
		// Valid IPv4
		{name: "valid IPv4", addr: "8.8.8.8", wantErr: nil},
		{name: "valid IPv4 zeros", addr: "0.0.0.0", wantErr: nil},
		{name: "valid IPv4 max", addr: "255.255.255.255", wantErr: nil},
		{name: "valid IPv4 localhost", addr: "127.0.0.1", wantErr: nil},

		// Valid IPv6
		{name: "valid IPv6", addr: "2001:4860:4860::8888", wantErr: nil},
		{name: "valid IPv6 full", addr: "2001:0db8:0000:0000:0000:0000:0000:0001", wantErr: nil},
		{name: "valid IPv6 loopback", addr: "::1", wantErr: nil},
		{name: "valid IPv6 all zeros", addr: "::", wantErr: nil},

		// Invalid
		{name: "empty string", addr: "", wantErr: ErrEmptyIP},
		{name: "invalid format", addr: "not-an-ip", wantErr: ErrInvalidIP},
		{name: "IPv4 out of range", addr: "256.256.256.256", wantErr: ErrInvalidIP},
		{name: "IPv4 too few octets", addr: "8.8.8", wantErr: ErrInvalidIP},
		{name: "IPv4 too many octets", addr: "8.8.8.8.8", wantErr: ErrInvalidIP},
		{name: "IPv4 with port", addr: "8.8.8.8:53", wantErr: ErrInvalidIP},
		{name: "IPv6 with port", addr: "[::1]:53", wantErr: ErrInvalidIP},
		{name: "domain name", addr: "example.com", wantErr: ErrInvalidIP},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIP(tt.addr)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidateIP(%q) = %v, want %v", tt.addr, err, tt.wantErr)
			}
		})
	}
}

func TestValidateASN(t *testing.T) {
	tests := []struct {
		name    string
		asn     uint64
		wantErr error
	}{
		// Valid ASNs
		{name: "minimum valid", asn: 1, wantErr: nil},
		{name: "typical ASN", asn: 15169, wantErr: nil},
		{name: "large 32-bit ASN", asn: 4294967295, wantErr: nil},

		// Invalid ASNs
		{name: "zero", asn: 0, wantErr: ErrASNOutOfRange},
		{name: "exceeds max", asn: 4294967296, wantErr: ErrASNOutOfRange},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateASN(tt.asn)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidateASN(%d) = %v, want %v", tt.asn, err, tt.wantErr)
			}
		})
	}
}

func TestValidateEntityHandle(t *testing.T) {
	tests := []struct {
		name    string
		handle  string
		wantErr error
	}{
		// Valid handles
		{name: "simple handle", handle: "ABC-123", wantErr: nil},
		{name: "ARIN handle", handle: "GOGL", wantErr: nil},
		{name: "RIPE handle", handle: "ORG-EXAM1-RIPE", wantErr: nil},
		{name: "with spaces", handle: "SOME HANDLE", wantErr: nil},
		{name: "special chars", handle: "HANDLE-!@#$%", wantErr: nil},

		// Invalid handles
		{name: "empty string", handle: "", wantErr: ErrEmptyHandle},
		{name: "too long", handle: strings.Repeat("a", 257), wantErr: ErrHandleTooLong},
		{name: "with newline", handle: "ABC\n123", wantErr: ErrInvalidHandleChar},
		{name: "with tab", handle: "ABC\t123", wantErr: ErrInvalidHandleChar},
		{name: "with null", handle: "ABC\x00123", wantErr: ErrInvalidHandleChar},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEntityHandle(tt.handle)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidateEntityHandle(%q) = %v, want %v", tt.handle, err, tt.wantErr)
			}
		})
	}
}

func TestValidateEntityHandle_MaxLength(t *testing.T) {
	// Test exactly max length
	maxHandle := strings.Repeat("a", MaxHandleLength)
	if err := ValidateEntityHandle(maxHandle); err != nil {
		t.Errorf("ValidateEntityHandle with %d chars should be valid, got %v", MaxHandleLength, err)
	}

	// Test one char over max
	tooLong := maxHandle + "a"
	if err := ValidateEntityHandle(tooLong); !errors.Is(err, ErrHandleTooLong) {
		t.Errorf("ValidateEntityHandle with %d chars should return ErrHandleTooLong, got %v", MaxHandleLength+1, err)
	}
}
