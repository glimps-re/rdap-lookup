package parsers

import (
	"testing"
)

func TestJPParser_Name(t *testing.T) {
	p := NewJPParser()
	if p.Name() != "jp" {
		t.Errorf("Name() = %q, want jp", p.Name())
	}
}

func TestJPParser_SupportsTLD(t *testing.T) {
	p := NewJPParser()

	tests := []struct {
		tld      string
		expected bool
	}{
		{"jp", true},
		{"JP", true},
		{"co.jp", true},
		{"or.jp", true},
		{"ne.jp", true},
		{"ac.jp", true},
		{"go.jp", true},
		{"com", false},
		{"de", false},
	}

	for _, tt := range tests {
		t.Run(tt.tld, func(t *testing.T) {
			if got := p.SupportsTLD(tt.tld); got != tt.expected {
				t.Errorf("SupportsTLD(%q) = %v, want %v", tt.tld, got, tt.expected)
			}
		})
	}
}

func TestJPParser_Parse_BasicDomain(t *testing.T) {
	p := NewJPParser()

	response := `[ JPRS database provides information on network administration. Its use is    ]
[ restricted to network administration purposes.                              ]

Domain Information: [ドメイン情報]
a. [ドメイン名]                 EXAMPLE.JP
g. [Organization]               Example Corporation
m. [登録担当者]                 XX12345JP
n. [技術連絡担当者]             YY67890JP
p. [ネームサーバ]               ns1.example.jp
p. [ネームサーバ]               ns2.example.jp
[状態]                          Active
[登録年月日]                    2000/01/15
[最終更新]                      2024/01/15 10:30:00 (JST)
`

	result, err := p.Parse(response, "example.jp")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	pd := result.Domain

	if pd.DomainName != "example.jp" {
		t.Errorf("DomainName = %q, want example.jp", pd.DomainName)
	}

	if len(pd.Nameservers) != 2 {
		t.Errorf("len(Nameservers) = %d, want 2", len(pd.Nameservers))
	} else if pd.Nameservers[0] != "ns1.example.jp" {
		t.Errorf("Nameservers[0] = %q, want ns1.example.jp", pd.Nameservers[0])
	}

	if len(pd.Status) != 1 || pd.Status[0] != "Active" {
		t.Errorf("Status = %v, want [Active]", pd.Status)
	}

	if pd.CreatedDate == nil || pd.CreatedDate.Year() != 2000 {
		t.Errorf("CreatedDate = %v, want year 2000", pd.CreatedDate)
	}

	if pd.UpdatedDate == nil || pd.UpdatedDate.Year() != 2024 {
		t.Errorf("UpdatedDate = %v, want year 2024", pd.UpdatedDate)
	}

	if pd.Registrant == nil || pd.Registrant.Organization != "Example Corporation" {
		t.Errorf("Registrant.Organization = %v, want Example Corporation", pd.Registrant)
	}

	if pd.TechContact == nil || pd.TechContact.Handle != "YY67890JP" {
		t.Errorf("TechContact.Handle = %v, want YY67890JP", pd.TechContact)
	}

	if result.Confidence != "high" {
		t.Errorf("Confidence = %q, want high", result.Confidence)
	}
}

func TestJPParser_Parse_NotFound(t *testing.T) {
	p := NewJPParser()

	tests := []struct {
		name     string
		response string
	}{
		{"No match", "No match!!\n"},
		{"Not found", "Not found\n"},
		{"No entries", "No entries found\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := p.Parse(tt.response, "notfound.jp")
			if err != nil {
				t.Fatalf("Parse error = %v", err)
			}

			if result.Confidence != "low" {
				t.Errorf("Confidence = %q, want low", result.Confidence)
			}
		})
	}
}

func TestJPParser_Parse_EmptyResponse(t *testing.T) {
	p := NewJPParser()

	result, err := p.Parse("", "example.jp")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	if result.Domain.DomainName != "example.jp" {
		t.Errorf("DomainName = %q, want example.jp", result.Domain.DomainName)
	}
}

func TestParseJPDate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantYear int
		wantNil  bool
	}{
		{"JPRS format with time", "2024/01/15 10:30:00", 2024, false},
		{"JPRS format date only", "2024/01/15", 2024, false},
		{"With JST suffix", "2024/01/15 10:30:00 (JST)", 2024, false},
		{"ISO format", "2024-01-15", 2024, false},
		{"Empty string", "", 0, true},
		{"Invalid", "not a date", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseJPDate(tt.input)
			if tt.wantNil {
				if result != nil {
					t.Errorf("parseJPDate(%q) = %v, want nil", tt.input, result)
				}
			} else {
				if result == nil {
					t.Errorf("parseJPDate(%q) = nil, want year %d", tt.input, tt.wantYear)
				} else if result.Year() != tt.wantYear {
					t.Errorf("parseJPDate(%q).Year() = %d, want %d", tt.input, result.Year(), tt.wantYear)
				}
			}
		})
	}
}

func TestNormalizeJPNameserver(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ns1.example.jp", "ns1.example.jp"},
		{"NS1.EXAMPLE.JP", "ns1.example.jp"},
		{"ns1.example.jp.", "ns1.example.jp"},
		{"ns1.example.jp 192.168.1.1", "ns1.example.jp"},
		{"example", ""}, // No dot
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeJPNameserver(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeJPNameserver(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestJPParser_Parse_DNSSEC(t *testing.T) {
	p := NewJPParser()

	response := `a. [ドメイン名]                 EXAMPLE.JP
s. [署名鍵]                     12345 3 13 ABC123...
`

	result, err := p.Parse(response, "example.jp")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	// When s. key is present with a value, DNSSEC should be signed
	if result.Domain.DNSSECSigned == nil || !*result.Domain.DNSSECSigned {
		t.Error("DNSSECSigned should be true when signing key is present")
	}
}

func BenchmarkJPParser_Parse(b *testing.B) {
	p := NewJPParser()

	response := `a. [ドメイン名]                 EXAMPLE.JP
g. [Organization]               Example Corporation
p. [ネームサーバ]               ns1.example.jp
p. [ネームサーバ]               ns2.example.jp
[状態]                          Active
[登録年月日]                    2000/01/15
`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = p.Parse(response, "example.jp")
	}
}
