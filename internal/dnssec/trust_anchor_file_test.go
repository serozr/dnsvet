package dnssec

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestLoadTrustAnchor(t *testing.T) {
	input := "; locally provisioned root trust anchor\n. 3600 IN DNSKEY 257 3 8 AwEAAcExampleKeyMaterial==\n"
	anchor, err := LoadTrustAnchor(strings.NewReader(input))
	if err != nil {
		t.Fatalf("LoadTrustAnchor() error = %v", err)
	}
	if anchor.Zone != "." || len(anchor.DNSKEYs) != 1 {
		t.Fatalf("unexpected trust anchor: zone=%q keys=%d", anchor.Zone, len(anchor.DNSKEYs))
	}
	if anchor.DNSKEYs[0].Protocol != 3 || anchor.DNSKEYs[0].Hdr.Rrtype != dns.TypeDNSKEY {
		t.Fatalf("unexpected DNSKEY: %+v", anchor.DNSKEYs[0])
	}
}

func TestLoadTrustAnchorAcceptsMultipleKeysForOneZone(t *testing.T) {
	input := ". 3600 IN DNSKEY 257 3 8 AwEAAcExampleKeyMaterial==\n. 3600 IN DNSKEY 257 3 13 AwEAAcOtherKeyMaterial==\n"
	anchor, err := LoadTrustAnchor(strings.NewReader(input))
	if err != nil {
		t.Fatalf("LoadTrustAnchor() error = %v", err)
	}
	if len(anchor.DNSKEYs) != 2 {
		t.Fatalf("keys = %d, want 2", len(anchor.DNSKEYs))
	}
}

func TestLoadTrustAnchorRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "empty", input: ""},
		{name: "non DNSKEY", input: ". 3600 IN DS 20326 8 2 1234"},
		{name: "wrong class", input: ". 3600 CH DNSKEY 257 3 8 AwEAAcExampleKeyMaterial=="},
		{name: "wrong protocol", input: ". 3600 IN DNSKEY 257 2 8 AwEAAcExampleKeyMaterial=="},
		{name: "multiple zones", input: ". 3600 IN DNSKEY 257 3 8 AwEAAcExampleKeyMaterial==\nexample.test. 3600 IN DNSKEY 257 3 8 AwEAAcExampleKeyMaterial=="},
		{name: "duplicate", input: ". 3600 IN DNSKEY 257 3 8 AwEAAcExampleKeyMaterial==\n. 3600 IN DNSKEY 257 3 8 AwEAAcExampleKeyMaterial=="},
		{name: "malformed", input: "not a DNS record"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := LoadTrustAnchor(strings.NewReader(test.input)); err == nil {
				t.Fatal("LoadTrustAnchor() error = nil, want rejection")
			}
		})
	}
}

func TestLoadTrustAnchorRejectsOversizedFile(t *testing.T) {
	input := strings.Repeat("; padding\n", maxTrustAnchorFileSize/8+1)
	if _, err := LoadTrustAnchor(strings.NewReader(input)); err == nil {
		t.Fatal("LoadTrustAnchor() error = nil, want size limit error")
	}
}

func TestLoadTrustAnchorRejectsTooManyKeys(t *testing.T) {
	var input strings.Builder
	for i := 0; i <= maxTrustAnchorKeys; i++ {
		input.WriteString(". 3600 IN DNSKEY 257 3 8 AwEAAcExampleKeyMaterial")
		input.WriteString(strings.Repeat("A", i+1))
		input.WriteString("==\n")
	}
	if _, err := LoadTrustAnchor(strings.NewReader(input.String())); err == nil {
		t.Fatal("LoadTrustAnchor() error = nil, want key count limit error")
	}
}

func TestLoadTrustAnchorRejectsDNSKEYWithoutZoneFlag(t *testing.T) {
	input := ". 3600 IN DNSKEY 1 3 8 AwEAAcExampleKeyMaterial==\n"
	if _, err := LoadTrustAnchor(strings.NewReader(input)); err == nil {
		t.Fatal("LoadTrustAnchor() error = nil, want DNSKEY Zone-flag rejection")
	}
}

func TestLoadTrustAnchorAcceptsMultilineMasterFileRecord(t *testing.T) {
	input := "; comment before the record\n\n. 3600 IN DNSKEY (\n  257 3 8 AwEAAcExampleKeyMaterial==\n) ; trailing comment\n"
	anchor, err := LoadTrustAnchor(strings.NewReader(input))
	if err != nil {
		t.Fatalf("LoadTrustAnchor() error = %v", err)
	}
	if anchor.Zone != "." || len(anchor.DNSKEYs) != 1 {
		t.Fatalf("unexpected trust anchor: zone=%q keys=%d", anchor.Zone, len(anchor.DNSKEYs))
	}
}
