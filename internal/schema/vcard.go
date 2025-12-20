// Package schema provides simplified response schemas and transformers for RDAP data.
package schema

import (
	"strings"
)

// Contact represents extracted contact information from a vCard.
type Contact struct {
	Name         string `json:"name,omitempty"`
	Organization string `json:"organization,omitempty"`
	Email        string `json:"email,omitempty"`
	Phone        string `json:"phone,omitempty"`
	Address      string `json:"address,omitempty"`
	Country      string `json:"country,omitempty"`
}

// ParseVCard extracts contact information from a jCard/vCard array.
// jCard format: ["vcard", [[property], [property], ...]]
// Each property: [name, params, type, value] or [name, params, type, value1, value2, ...]
func ParseVCard(vcardArray []any) Contact {
	var contact Contact

	if len(vcardArray) < 2 {
		return contact
	}

	// First element should be "vcard"
	if tag, ok := vcardArray[0].(string); !ok || tag != "vcard" {
		return contact
	}

	// Second element is array of properties
	properties, ok := vcardArray[1].([]any)
	if !ok {
		return contact
	}

	for _, prop := range properties {
		propArray, ok := prop.([]any)
		if !ok || len(propArray) < 4 {
			continue
		}

		propName, ok := propArray[0].(string)
		if !ok {
			continue
		}

		switch strings.ToLower(propName) {
		case "fn":
			contact.Name = extractStringValue(propArray, 3)
		case "org":
			contact.Organization = extractStringValue(propArray, 3)
		case "email":
			contact.Email = extractStringValue(propArray, 3)
		case "tel":
			contact.Phone = extractStringValue(propArray, 3)
		case "adr":
			contact.Address, contact.Country = extractAddress(propArray)
		}
	}

	return contact
}

// extractStringValue extracts a string value from a property array at the given index.
func extractStringValue(propArray []any, index int) string {
	if index >= len(propArray) {
		return ""
	}

	switch v := propArray[index].(type) {
	case string:
		return v
	case []any:
		// Some values come as arrays
		if len(v) > 0 {
			if s, ok := v[0].(string); ok {
				return s
			}
		}
	}
	return ""
}

// extractAddress extracts address and country from an adr property.
// ADR format: [name, params, type, [pobox, ext, street, locality, region, postal, country]]
func extractAddress(propArray []any) (address, country string) {
	if len(propArray) < 4 {
		return "", ""
	}

	// ADR value can be a single array or multiple values
	adrValue := propArray[3]

	switch v := adrValue.(type) {
	case []any:
		// Standard jCard format: array of address components
		parts := make([]string, 0, len(v))
		for i, part := range v {
			s := anyToString(part)
			if s != "" {
				parts = append(parts, s)
			}
			// Country is the last element (index 6)
			if i == 6 && s != "" {
				country = s
			}
		}
		address = strings.Join(parts, ", ")
	case string:
		address = v
	}

	return address, country
}

// maxVCardDepth limits recursion depth to prevent stack overflow.
const maxVCardDepth = 10

// anyToString converts an any value to string, handling nested arrays.
func anyToString(v any) string {
	return anyToStringWithDepth(v, 0)
}

// anyToStringWithDepth converts an any value to string with depth limit.
func anyToStringWithDepth(v any, depth int) string {
	if depth > maxVCardDepth {
		return ""
	}
	switch s := v.(type) {
	case string:
		return s
	case []any:
		// Some registries nest values in arrays
		if len(s) > 0 {
			return anyToStringWithDepth(s[0], depth+1)
		}
	}
	return ""
}
