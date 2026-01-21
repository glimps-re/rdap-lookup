package parsers

import (
	"testing"
)

func TestESParser_Name(t *testing.T) {
	p := NewESParser()
	if p.Name() != "es" {
		t.Errorf("Name() = %q, want es", p.Name())
	}
}

func TestESParser_SupportsTLD(t *testing.T) {
	p := NewESParser()

	tests := []struct {
		tld      string
		expected bool
	}{
		{"es", true},
		{"ES", true},
		{"com.es", true},
		{"org.es", true},
		{"nom.es", true},
		{"gob.es", true},
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

func TestESParser_Parse_BasicDomain(t *testing.T) {
	p := NewESParser()

	response := `Nombre de dominio / Domain name: example.es

INFORMACIÓN DEL TITULAR / HOLDER INFORMATION
Tipo de identificación / Identification Type: NIF/NIE
Identificación / Identification: ***
Nombre / Name: ***

INFORMACIÓN DEL AGENTE REGISTRADOR / REGISTRAR INFORMATION
Nombre / Name: Example Registrar, S.L.
URL: https://www.example-registrar.es

INFORMACIÓN TÉCNICA DEL DOMINIO / TECHNICAL INFORMATION
Servidores DNS / DNS Servers:
   ns1.example.es
   ns2.example.es

Estado del dominio / Domain Status: activo/active
Fecha de creación / Creation Date: 01/01/2000
Fecha de caducidad / Expiration Date: 01/01/2025
`

	result, err := p.Parse(response, "example.es")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	pd := result.Domain

	if pd.DomainName != "example.es" {
		t.Errorf("DomainName = %q, want example.es", pd.DomainName)
	}

	if len(pd.Nameservers) != 2 {
		t.Errorf("len(Nameservers) = %d, want 2", len(pd.Nameservers))
	} else if pd.Nameservers[0] != "ns1.example.es" {
		t.Errorf("Nameservers[0] = %q, want ns1.example.es", pd.Nameservers[0])
	}

	if pd.CreatedDate == nil || pd.CreatedDate.Year() != 2000 {
		t.Errorf("CreatedDate = %v, want year 2000", pd.CreatedDate)
	}

	if pd.ExpirationDate == nil || pd.ExpirationDate.Year() != 2025 {
		t.Errorf("ExpirationDate = %v, want year 2025", pd.ExpirationDate)
	}

	if pd.Registrar == nil || pd.Registrar.Name != "Example Registrar, S.L." {
		t.Errorf("Registrar.Name = %v, want Example Registrar, S.L.", pd.Registrar)
	}

	if result.Confidence != "high" {
		t.Errorf("Confidence = %q, want high", result.Confidence)
	}
}

func TestESParser_Parse_NotFound(t *testing.T) {
	p := NewESParser()

	tests := []struct {
		name     string
		response string
	}{
		{"No existe", "El dominio no existe\n"},
		{"Does not exist", "Domain does not exist\n"},
		{"Not found", "Not found\n"},
		{"No match", "No match for domain\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := p.Parse(tt.response, "notfound.es")
			if err != nil {
				t.Fatalf("Parse error = %v", err)
			}

			if result.Confidence != "low" {
				t.Errorf("Confidence = %q, want low", result.Confidence)
			}
		})
	}
}

func TestESParser_Parse_EmptyResponse(t *testing.T) {
	p := NewESParser()

	result, err := p.Parse("", "example.es")
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}

	if result.Domain.DomainName != "example.es" {
		t.Errorf("DomainName = %q, want example.es", result.Domain.DomainName)
	}
}

func TestParseESDate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantYear int
		wantNil  bool
	}{
		{"DD/MM/YYYY", "01/01/2000", 2000, false},
		{"D/M/YYYY", "1/1/2000", 2000, false},
		{"YYYY-MM-DD", "2024-01-15", 2024, false},
		{"Empty string", "", 0, true},
		{"Invalid", "not a date", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseESDate(tt.input)
			if tt.wantNil {
				if result != nil {
					t.Errorf("parseESDate(%q) = %v, want nil", tt.input, result)
				}
			} else {
				if result == nil {
					t.Errorf("parseESDate(%q) = nil, want year %d", tt.input, tt.wantYear)
				} else if result.Year() != tt.wantYear {
					t.Errorf("parseESDate(%q).Year() = %d, want %d", tt.input, result.Year(), tt.wantYear)
				}
			}
		})
	}
}

func TestNormalizeESNameserver(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ns1.example.es", "ns1.example.es"},
		{"NS1.EXAMPLE.ES", "ns1.example.es"},
		{"ns1.example.es.", "ns1.example.es"},
		{"example", ""}, // No dot
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeESNameserver(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeESNameserver(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func BenchmarkESParser_Parse(b *testing.B) {
	p := NewESParser()

	response := `Nombre de dominio / Domain name: example.es
INFORMACIÓN DEL AGENTE REGISTRADOR / REGISTRAR INFORMATION
Nombre / Name: Example Registrar, S.L.
INFORMACIÓN TÉCNICA DEL DOMINIO / TECHNICAL INFORMATION
Servidores DNS / DNS Servers:
   ns1.example.es
   ns2.example.es
Fecha de creación / Creation Date: 01/01/2000
Fecha de caducidad / Expiration Date: 01/01/2025
`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = p.Parse(response, "example.es")
	}
}
