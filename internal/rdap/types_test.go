package rdap

import (
	"testing"
	"time"
)

func TestStatus_Contains(t *testing.T) {
	status := Status{"active", "client delete prohibited"}

	t.Run("contains existing", func(t *testing.T) {
		if !status.Contains("active") {
			t.Error("expected to contain 'active'")
		}
	})

	t.Run("does not contain missing", func(t *testing.T) {
		if status.Contains("inactive") {
			t.Error("expected not to contain 'inactive'")
		}
	})

	t.Run("empty status", func(t *testing.T) {
		empty := Status{}
		if empty.Contains("anything") {
			t.Error("expected empty status to not contain anything")
		}
	})
}

func TestEvent_ParsedEventDate(t *testing.T) {
	t.Run("valid RFC3339 date", func(t *testing.T) {
		event := Event{
			EventAction: "registration",
			EventDate:   "2020-01-15T12:00:00Z",
		}
		parsed, err := event.ParsedEventDate()
		if err != nil {
			t.Fatalf("ParsedEventDate error: %v", err)
		}
		expected := time.Date(2020, 1, 15, 12, 0, 0, 0, time.UTC)
		if !parsed.Equal(expected) {
			t.Errorf("parsed = %v, want %v", parsed, expected)
		}
	})

	t.Run("invalid date format", func(t *testing.T) {
		event := Event{
			EventAction: "registration",
			EventDate:   "2020/01/15",
		}
		_, err := event.ParsedEventDate()
		if err == nil {
			t.Error("expected error for invalid date format")
		}
	})

	t.Run("empty date", func(t *testing.T) {
		event := Event{
			EventAction: "registration",
			EventDate:   "",
		}
		_, err := event.ParsedEventDate()
		if err == nil {
			t.Error("expected error for empty date")
		}
	})
}

func TestDomainResponse_Fields(t *testing.T) {
	resp := DomainResponse{
		ObjectClassName: "domain",
		Handle:          "DOM123",
		LDHName:         "example.com",
		UnicodeName:     "example.com",
		Status:          Status{"active", "clientDeleteProhibited"},
		Nameservers: []Nameserver{
			{
				LDHName: "ns1.example.com",
				IPAddresses: &IPAddrs{
					V4: []string{"192.0.2.1"},
					V6: []string{"2001:db8::1"},
				},
			},
		},
		Events: []Event{
			{EventAction: "registration", EventDate: "2010-01-01T00:00:00Z"},
			{EventAction: "expiration", EventDate: "2025-01-01T00:00:00Z"},
		},
		SecureDNS: &SecureDNS{
			DelegationSigned: boolPtr(true),
		},
	}

	if resp.LDHName != "example.com" {
		t.Errorf("LDHName = %q, want %q", resp.LDHName, "example.com")
	}

	if len(resp.Nameservers) != 1 {
		t.Errorf("len(Nameservers) = %d, want 1", len(resp.Nameservers))
	}

	if resp.SecureDNS == nil || resp.SecureDNS.DelegationSigned == nil || !*resp.SecureDNS.DelegationSigned {
		t.Error("expected SecureDNS.DelegationSigned to be true")
	}

	if !resp.Status.Contains("active") {
		t.Error("expected status to contain 'active'")
	}
}

func TestIPResponse_Fields(t *testing.T) {
	resp := IPResponse{
		ObjectClassName: "ip network",
		Handle:          "NET-192-0-2-0-1",
		StartAddress:    "192.0.2.0",
		EndAddress:      "192.0.2.255",
		IPVersion:       "v4",
		Name:            "TEST-NET-1",
		Country:         "US",
		CIDR0Cidrs: []CIDR{
			{V4Prefix: "192.0.2.0", Length: 24},
		},
	}

	if resp.IPVersion != "v4" {
		t.Errorf("IPVersion = %q, want %q", resp.IPVersion, "v4")
	}

	if resp.Country != "US" {
		t.Errorf("Country = %q, want %q", resp.Country, "US")
	}

	if len(resp.CIDR0Cidrs) != 1 {
		t.Errorf("len(CIDR0Cidrs) = %d, want 1", len(resp.CIDR0Cidrs))
	}
}

func TestASNResponse_Fields(t *testing.T) {
	resp := ASNResponse{
		ObjectClassName: "autnum",
		Handle:          "AS15169",
		StartAutnum:     15169,
		EndAutnum:       15169,
		Name:            "GOOGLE",
		Country:         "US",
	}

	if resp.StartAutnum != 15169 {
		t.Errorf("StartAutnum = %d, want 15169", resp.StartAutnum)
	}

	if resp.Name != "GOOGLE" {
		t.Errorf("Name = %q, want %q", resp.Name, "GOOGLE")
	}
}

func TestEntityResponse_Fields(t *testing.T) {
	resp := EntityResponse{
		ObjectClassName: "entity",
		Handle:          "REG123-VRSN",
		Roles:           []string{"registrar", "sponsor"},
		PublicIDs: []PublicID{
			{Type: "IANA Registrar ID", Identifier: "123"},
		},
	}

	if len(resp.Roles) != 2 {
		t.Errorf("len(Roles) = %d, want 2", len(resp.Roles))
	}

	if len(resp.PublicIDs) != 1 {
		t.Errorf("len(PublicIDs) = %d, want 1", len(resp.PublicIDs))
	}
}

func TestNameserverResponse_Fields(t *testing.T) {
	resp := NameserverResponse{
		ObjectClassName: "nameserver",
		Handle:          "NS123",
		LDHName:         "ns1.example.com",
		IPAddresses: &IPAddrs{
			V4: []string{"192.0.2.1", "192.0.2.2"},
			V6: []string{"2001:db8::1"},
		},
	}

	if resp.LDHName != "ns1.example.com" {
		t.Errorf("LDHName = %q, want %q", resp.LDHName, "ns1.example.com")
	}

	if resp.IPAddresses == nil {
		t.Fatal("expected IPAddresses to be non-nil")
	}

	if len(resp.IPAddresses.V4) != 2 {
		t.Errorf("len(V4) = %d, want 2", len(resp.IPAddresses.V4))
	}
}

func boolPtr(b bool) *bool {
	return &b
}
