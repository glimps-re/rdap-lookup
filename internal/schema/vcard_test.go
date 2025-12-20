package schema

import (
	"testing"
)

func TestParseVCard(t *testing.T) {
	tests := []struct {
		name     string
		vcard    []any
		expected Contact
	}{
		{
			name:     "empty vcard",
			vcard:    []any{},
			expected: Contact{},
		},
		{
			name:     "invalid first element",
			vcard:    []any{"notavcard", []any{}},
			expected: Contact{},
		},
		{
			name: "basic vcard with fn and email",
			vcard: []any{
				"vcard",
				[]any{
					[]any{"version", map[string]any{}, "text", "4.0"},
					[]any{"fn", map[string]any{}, "text", "John Doe"},
					[]any{"email", map[string]any{}, "text", "john@example.com"},
				},
			},
			expected: Contact{
				Name:  "John Doe",
				Email: "john@example.com",
			},
		},
		{
			name: "full vcard with all fields",
			vcard: []any{
				"vcard",
				[]any{
					[]any{"version", map[string]any{}, "text", "4.0"},
					[]any{"fn", map[string]any{}, "text", "Jane Smith"},
					[]any{"org", map[string]any{}, "text", "Example Corp"},
					[]any{"email", map[string]any{}, "text", "jane@example.com"},
					[]any{"tel", map[string]any{"type": "voice"}, "uri", "+1-555-123-4567"},
					[]any{"adr", map[string]any{}, "text", []any{"", "", "123 Main St", "Anytown", "CA", "12345", "US"}},
				},
			},
			expected: Contact{
				Name:         "Jane Smith",
				Organization: "Example Corp",
				Email:        "jane@example.com",
				Phone:        "+1-555-123-4567",
				Address:      "123 Main St, Anytown, CA, 12345, US",
				Country:      "US",
			},
		},
		{
			name: "vcard with mixed case property names",
			vcard: []any{
				"vcard",
				[]any{
					[]any{"FN", map[string]any{}, "text", "Test User"},
					[]any{"EMAIL", map[string]any{}, "text", "test@test.com"},
					[]any{"ORG", map[string]any{}, "text", "Test Org"},
				},
			},
			expected: Contact{
				Name:         "Test User",
				Email:        "test@test.com",
				Organization: "Test Org",
			},
		},
		{
			name: "vcard with array value for org",
			vcard: []any{
				"vcard",
				[]any{
					[]any{"fn", map[string]any{}, "text", "Test"},
					[]any{"org", map[string]any{}, "text", []any{"Array Org"}},
				},
			},
			expected: Contact{
				Name:         "Test",
				Organization: "Array Org",
			},
		},
		{
			name: "vcard with partial address (no country)",
			vcard: []any{
				"vcard",
				[]any{
					[]any{"fn", map[string]any{}, "text", "No Country"},
					[]any{"adr", map[string]any{}, "text", []any{"", "", "Street", "City", "State", "Zip"}},
				},
			},
			expected: Contact{
				Name:    "No Country",
				Address: "Street, City, State, Zip",
				Country: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseVCard(tt.vcard)

			if result.Name != tt.expected.Name {
				t.Errorf("Name = %q, want %q", result.Name, tt.expected.Name)
			}
			if result.Organization != tt.expected.Organization {
				t.Errorf("Organization = %q, want %q", result.Organization, tt.expected.Organization)
			}
			if result.Email != tt.expected.Email {
				t.Errorf("Email = %q, want %q", result.Email, tt.expected.Email)
			}
			if result.Phone != tt.expected.Phone {
				t.Errorf("Phone = %q, want %q", result.Phone, tt.expected.Phone)
			}
			if result.Country != tt.expected.Country {
				t.Errorf("Country = %q, want %q", result.Country, tt.expected.Country)
			}
		})
	}
}

func TestAnyToString(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected string
	}{
		{"string", "hello", "hello"},
		{"empty string", "", ""},
		{"array with string", []any{"world"}, "world"},
		{"empty array", []any{}, ""},
		{"nested array", []any{[]any{"nested"}}, "nested"},
		{"nil", nil, ""},
		{"number", 123, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := anyToString(tt.input)
			if result != tt.expected {
				t.Errorf("anyToString(%v) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestAnyToStringDepthLimit(t *testing.T) {
	// Test that deeply nested arrays don't cause stack overflow
	// Build a deeply nested structure that exceeds maxVCardDepth
	var deepNested any = "deep value"
	for i := 0; i < 20; i++ { // 20 levels of nesting, exceeds maxVCardDepth of 10
		deepNested = []any{deepNested}
	}

	// Should return empty string due to depth limit, not the value
	result := anyToString(deepNested)
	if result != "" {
		t.Errorf("deeply nested anyToString should return empty due to depth limit, got %q", result)
	}

	// Test that nesting at exactly maxVCardDepth works
	var okNested any = "ok value"
	for i := 0; i < maxVCardDepth; i++ {
		okNested = []any{okNested}
	}

	result = anyToString(okNested)
	if result != "ok value" {
		t.Errorf("anyToString at maxVCardDepth should return value, got %q", result)
	}

	// Test that nesting at maxVCardDepth + 1 returns empty
	var tooDeep any = "too deep"
	for i := 0; i <= maxVCardDepth; i++ { // One more than maxVCardDepth
		tooDeep = []any{tooDeep}
	}

	result = anyToString(tooDeep)
	if result != "" {
		t.Errorf("anyToString beyond maxVCardDepth should return empty, got %q", result)
	}
}
