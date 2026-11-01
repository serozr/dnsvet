package dnssec

import (
	"crypto"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func signedDNSKEYSet(t *testing.T, at time.Time) (RRset, *dns.RRSIG, *dns.DNSKEY) {
	t.Helper()

	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ED25519,
	}
	privateKey, err := key.Generate(256)
	if err != nil {
		t.Fatalf("DNSKEY.Generate(): %v", err)
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		t.Fatal("generated private key does not implement crypto.Signer")
	}

	rrset := RRset{
		Name:  "example.test.",
		Class: dns.ClassINET,
		Type:  dns.TypeDNSKEY,
		Records: []dns.RR{
			key,
		},
	}
	signature := &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		Algorithm:  dns.ED25519,
		Expiration: uint32(at.Add(time.Hour).Unix()),
		Inception:  uint32(at.Add(-time.Hour).Unix()),
		KeyTag:     key.KeyTag(),
		SignerName: "example.test.",
	}
	if err := signature.Sign(signer, rrset.Records); err != nil {
		t.Fatalf("RRSIG.Sign(): %v", err)
	}
	return rrset, signature, key
}

func TestValidateTrustAnchorDNSKEYSetAcceptsPinnedKey(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, key := signedDNSKEYSet(t, at)

	keys, err := ValidateTrustAnchorDNSKEYSet(
		rrset,
		[]*dns.RRSIG{signature},
		TrustAnchor{Zone: "example.test.", DNSKEY: key},
		at,
	)
	if err != nil {
		t.Fatalf("ValidateTrustAnchorDNSKEYSet() error = %v", err)
	}
	if len(keys) != 1 || !sameDNSKEY(keys[0], key) {
		t.Fatalf("authenticated keys = %v, want the pinned DNSKEY", keys)
	}
}

func TestValidateTrustAnchorDNSKEYSetRejectsUnpinnedKey(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, _ := signedDNSKEYSet(t, at)
	_, _, otherKey := signedDNSKEYSet(t, at)

	_, err := ValidateTrustAnchorDNSKEYSet(
		rrset,
		[]*dns.RRSIG{signature},
		TrustAnchor{Zone: "example.test.", DNSKEY: otherKey},
		at,
	)
	if err == nil || !strings.Contains(err.Error(), "absent") {
		t.Fatalf("error = %v, want absent trust anchor error", err)
	}
}

func TestValidateTrustAnchorDNSKEYSetRejectsTamperedSignature(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, key := signedDNSKEYSet(t, at)
	rrset.Records[0].(*dns.DNSKEY).PublicKey = key.PublicKey + "A"

	_, err := ValidateTrustAnchorDNSKEYSet(
		rrset,
		[]*dns.RRSIG{signature},
		TrustAnchor{Zone: "example.test.", DNSKEY: key},
		at,
	)
	if err == nil {
		t.Fatal("ValidateTrustAnchorDNSKEYSet() error = nil, want signature failure")
	}
}

func TestValidateTrustAnchorDNSKEYSetRejectsWrongZone(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, key := signedDNSKEYSet(t, at)

	_, err := ValidateTrustAnchorDNSKEYSet(
		rrset,
		[]*dns.RRSIG{signature},
		TrustAnchor{Zone: "other.test.", DNSKEY: key},
		at,
	)
	if err == nil {
		t.Fatal("ValidateTrustAnchorDNSKEYSet() error = nil, want zone mismatch")
	}
}

func TestValidateTrustAnchorDNSKEYSetRejectsMissingAnchor(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, key := signedDNSKEYSet(t, at)
	rrset.Records = nil

	_, err := ValidateTrustAnchorDNSKEYSet(
		rrset,
		[]*dns.RRSIG{signature},
		TrustAnchor{Zone: "example.test.", DNSKEY: key},
		at,
	)
	if err == nil {
		t.Fatal("ValidateTrustAnchorDNSKEYSet() error = nil, want empty RRset error")
	}
}

func TestValidateTrustAnchorDNSKEYSetIgnoresNonProtocolThreeRecords(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	key, signer := makeSigningKey(t, "example.test.")
	invalidKey := *key
	invalidKey.Protocol = 2
	rrset := RRset{
		Name: "example.test.", Class: dns.ClassINET, Type: dns.TypeDNSKEY,
		Records: []dns.RR{key, &invalidKey},
	}
	signature := signTestRRset(t, rrset, key, signer, at)

	keys, err := ValidateTrustAnchorDNSKEYSet(
		rrset, []*dns.RRSIG{signature},
		TrustAnchor{Zone: "example.test.", DNSKEY: key}, at,
	)
	if err != nil {
		t.Fatalf("ValidateTrustAnchorDNSKEYSet() error = %v", err)
	}
	if len(keys) != 1 || !sameDNSKEY(keys[0], key) {
		t.Fatalf("usable keys = %d, want only the valid protocol-3 key", len(keys))
	}
}

func TestValidateTrustAnchorDNSKEYSetAcceptsMultipleConfiguredAnchors(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	firstKey, _ := makeSigningKey(t, "example.test.")
	secondKey, secondSigner := makeSigningKey(t, "example.test.")
	rrset := RRset{
		Name: "example.test.", Class: dns.ClassINET, Type: dns.TypeDNSKEY,
		Records: []dns.RR{firstKey, secondKey},
	}
	signature := signTestRRset(t, rrset, secondKey, secondSigner, at)

	keys, err := ValidateTrustAnchorDNSKEYSet(
		rrset, []*dns.RRSIG{signature},
		TrustAnchor{Zone: "example.test.", DNSKEYs: []*dns.DNSKEY{firstKey, secondKey}},
		at,
	)
	if err != nil {
		t.Fatalf("ValidateTrustAnchorDNSKEYSet() error = %v", err)
	}
	if len(keys) != 2 || !containsDNSKEY(keys, firstKey) || !containsDNSKEY(keys, secondKey) {
		t.Fatalf("authenticated keys = %d, want both configured zone keys", len(keys))
	}
}

func TestValidateTrustAnchorDNSKEYSetUsesPresentAnchorDuringRollover(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	retiredKey, _ := makeSigningKey(t, "example.test.")
	activeKey, activeSigner := makeSigningKey(t, "example.test.")
	rrset := RRset{
		Name: "example.test.", Class: dns.ClassINET, Type: dns.TypeDNSKEY,
		Records: []dns.RR{activeKey},
	}
	signature := signTestRRset(t, rrset, activeKey, activeSigner, at)

	_, err := ValidateTrustAnchorDNSKEYSet(
		rrset, []*dns.RRSIG{signature},
		TrustAnchor{Zone: "example.test.", DNSKEYs: []*dns.DNSKEY{retiredKey, activeKey}},
		at,
	)
	if err != nil {
		t.Fatalf("ValidateTrustAnchorDNSKEYSet() should accept the present active anchor: %v", err)
	}
}

func TestValidateTrustAnchorDNSKEYSetRejectsWhenNoConfiguredAnchorIsPresent(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, _ := signedDNSKEYSet(t, at)
	_, _, otherKey := signedDNSKEYSet(t, at)

	_, err := ValidateTrustAnchorDNSKEYSet(
		rrset, []*dns.RRSIG{signature},
		TrustAnchor{Zone: "example.test.", DNSKEYs: []*dns.DNSKEY{otherKey}},
		at,
	)
	if err == nil || !strings.Contains(err.Error(), "none of the configured") {
		t.Fatalf("error = %v, want no configured anchor present error", err)
	}
}

func TestValidateTrustAnchorDNSKEYSetRejectsNilConfiguredAnchor(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, key := signedDNSKEYSet(t, at)

	_, err := ValidateTrustAnchorDNSKEYSet(
		rrset, []*dns.RRSIG{signature},
		TrustAnchor{Zone: "example.test.", DNSKEYs: []*dns.DNSKEY{key, nil}},
		at,
	)
	if err == nil || !strings.Contains(err.Error(), "is nil") {
		t.Fatalf("error = %v, want nil configured anchor rejection", err)
	}
}

