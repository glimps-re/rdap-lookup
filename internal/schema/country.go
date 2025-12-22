package schema

import (
	"strings"

	openrdap "github.com/openrdap/rdap"
)

// ExtractCountryFromDomain extracts the country from a domain response.
// Priority: registrant vCard country > admin contact country > tech contact country.
func ExtractCountryFromDomain(resp *openrdap.Domain) string {
	if resp == nil {
		return ""
	}

	// Try to find country from entities in priority order
	priorities := []string{"registrant", "administrative", "technical"}

	for _, priority := range priorities {
		for i := range resp.Entities {
			for _, role := range resp.Entities[i].Roles {
				if role == priority {
					country := extractCountryFromEntity(&resp.Entities[i])
					if country != "" {
						return country
					}
				}
			}
		}
	}

	return ""
}

// ExtractCountryFromIP extracts the country from an IP response.
// Priority: IP country field > registrant vCard country > abuse contact country.
func ExtractCountryFromIP(resp *openrdap.IPNetwork) string {
	if resp == nil {
		return ""
	}

	// First check the direct country field
	if resp.Country != "" {
		return normalizeCountry(resp.Country)
	}

	// Try entities in priority order
	priorities := []string{"registrant", "abuse", "administrative", "technical"}

	for _, priority := range priorities {
		for i := range resp.Entities {
			for _, role := range resp.Entities[i].Roles {
				if role == priority {
					country := extractCountryFromEntity(&resp.Entities[i])
					if country != "" {
						return country
					}
				}
			}
		}
	}

	return ""
}

// ExtractCountryFromASN extracts the country from an ASN response.
// Priority: ASN country field > registrant vCard country > admin contact country.
func ExtractCountryFromASN(resp *openrdap.Autnum) string {
	if resp == nil {
		return ""
	}

	// First check the direct country field
	if resp.Country != "" {
		return normalizeCountry(resp.Country)
	}

	// Try entities in priority order
	priorities := []string{"registrant", "administrative", "technical", "abuse"}

	for _, priority := range priorities {
		for i := range resp.Entities {
			for _, role := range resp.Entities[i].Roles {
				if role == priority {
					country := extractCountryFromEntity(&resp.Entities[i])
					if country != "" {
						return country
					}
				}
			}
		}
	}

	return ""
}

// ExtractCountryFromEntityResponse extracts the country from an entity response.
func ExtractCountryFromEntityResponse(resp *openrdap.Entity) string {
	if resp == nil {
		return ""
	}

	// Extract country from VCard
	if resp.VCard != nil {
		if country := resp.VCard.Country(); country != "" {
			return normalizeCountry(country)
		}
	}

	// Check nested entities
	for i := range resp.Entities {
		country := extractCountryFromEntity(&resp.Entities[i])
		if country != "" {
			return country
		}
	}

	// Check related networks
	for _, network := range resp.Networks {
		if network.Country != "" {
			return normalizeCountry(network.Country)
		}
	}

	// Check related ASNs
	for _, autnum := range resp.Autnums {
		if autnum.Country != "" {
			return normalizeCountry(autnum.Country)
		}
	}

	return ""
}

// maxEntityDepth limits recursion depth when extracting country from nested entities.
// This prevents stack overflow from maliciously crafted deeply nested structures.
const maxEntityDepth = 10

// extractCountryFromEntity extracts country from a single entity.
func extractCountryFromEntity(entity *openrdap.Entity) string {
	return extractCountryFromEntityWithDepth(entity, 0)
}

// extractCountryFromEntityWithDepth extracts country with recursion depth tracking.
func extractCountryFromEntityWithDepth(entity *openrdap.Entity, depth int) string {
	if entity == nil || depth > maxEntityDepth {
		return ""
	}

	// Extract country from VCard
	if entity.VCard != nil {
		if country := entity.VCard.Country(); country != "" {
			return normalizeCountry(country)
		}
	}

	// Check nested entities recursively with depth limit
	for i := range entity.Entities {
		country := extractCountryFromEntityWithDepth(&entity.Entities[i], depth+1)
		if country != "" {
			return country
		}
	}

	return ""
}

// countryNameToCode maps common country names to ISO 3166-1 alpha-2 codes.
// This map is initialized once at package level to avoid allocation on each call.
var countryNameToCode = map[string]string{
	"UNITED STATES":            "US",
	"UNITED STATES OF AMERICA": "US",
	"USA":                      "US",
	"UNITED KINGDOM":           "GB",
	"GREAT BRITAIN":            "GB",
	"GERMANY":                  "DE",
	"DEUTSCHLAND":              "DE",
	"FRANCE":                   "FR",
	"JAPAN":                    "JP",
	"CHINA":                    "CN",
	"AUSTRALIA":                "AU",
	"CANADA":                   "CA",
	"BRAZIL":                   "BR",
	"INDIA":                    "IN",
	"RUSSIA":                   "RU",
	"RUSSIAN FEDERATION":       "RU",
	"NETHERLANDS":              "NL",
	"THE NETHERLANDS":          "NL",
	"SPAIN":                    "ES",
	"ITALY":                    "IT",
	"SWEDEN":                   "SE",
	"SWITZERLAND":              "CH",
	"POLAND":                   "PL",
	"SOUTH KOREA":              "KR",
	"KOREA, REPUBLIC OF":       "KR",
	"REPUBLIC OF KOREA":        "KR",
	"SINGAPORE":                "SG",
	"HONG KONG":                "HK",
	"TAIWAN":                   "TW",
	"MEXICO":                   "MX",
	"IRELAND":                  "IE",
	"BELGIUM":                  "BE",
	"AUSTRIA":                  "AT",
	"NORWAY":                   "NO",
	"DENMARK":                  "DK",
	"FINLAND":                  "FI",
	"NEW ZEALAND":              "NZ",
	"PORTUGAL":                 "PT",
	"CZECH REPUBLIC":           "CZ",
	"CZECHIA":                  "CZ",
	"ISRAEL":                   "IL",
	"SOUTH AFRICA":             "ZA",
	"ARGENTINA":                "AR",
	"CHILE":                    "CL",
	"COLOMBIA":                 "CO",
	"VIETNAM":                  "VN",
	"VIET NAM":                 "VN",
	"THAILAND":                 "TH",
	"INDONESIA":                "ID",
	"MALAYSIA":                 "MY",
	"PHILIPPINES":              "PH",
	"UKRAINE":                  "UA",
	"ROMANIA":                  "RO",
	"GREECE":                   "GR",
	"HUNGARY":                  "HU",
	"TURKEY":                   "TR",
	"EGYPT":                    "EG",
	"UNITED ARAB EMIRATES":     "AE",
	"UAE":                      "AE",
	"SAUDI ARABIA":             "SA",
}

// normalizeCountry normalizes a country code/name to uppercase ISO 3166-1 alpha-2.
func normalizeCountry(country string) string {
	country = strings.TrimSpace(country)
	country = strings.ToUpper(country)

	// If it's already a 2-letter code, return it
	if len(country) == 2 {
		return country
	}

	// Lookup in pre-built map
	if code, ok := countryNameToCode[country]; ok {
		return code
	}

	// Return original if no mapping found
	return country
}
