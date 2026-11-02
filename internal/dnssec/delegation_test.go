package dnssec

import (
	"crypto"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func makeSigningKey(t *testing.T, zone string) (*dns.DNSKEY, crypto.Signer) {
	return makeSigningKeyWithFlags(t, zone, 257)
}

func makeSigningKeyWithFlags(t *testing.T, zone string, flags uint16) (*dns.DNSKEY, crypto.Signer) {
	t.Helper()
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     flags,
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
	return key, signer
}

func TestValidateDelegationDSRejectsNonZoneChildKey(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	parentKey, parentSigner := makeSigningKey(t, "test.")
	childKey, _ := makeSigningKeyWithFlags(t, "example.test.", 1)
	dsSet := RRset{
		Name: "example.test.", Class: dns.ClassINET, Type: dns.TypeDS,
		Records: []dns.RR{childKey.ToDS(dns.SHA256)},
	}
	signature := signTestRRset(t, dsSet, parentKey, parentSigner, at)

	_, err := ValidateDelegationDS(
		"test.", dsSet, []*dns.RRSIG{signature},
		[]*dns.DNSKEY{parentKey}, []*dns.DNSKEY{childKey}, at,
	)
	if !errors.Is(err, ErrNoDelegationKey) {
		t.Fatalf("error = %v, want ErrNoDelegationKey", err)
	}
}

func signedDelegationDS(t *testing.T, at time.Time) (RRset, *dns.RRSIG, *dns.DNSKEY, *dns.DNSKEY, crypto.Signer) {
	t.Helper()
	return signedDelegationDSForZones(t, at, "test.", "example.test.")
}

func signedDelegationDSForZones(
	t *testing.T,
	at time.Time,
	parentZone string,
	childZone string,
) (RRset, *dns.RRSIG, *dns.DNSKEY, *dns.DNSKEY, crypto.Signer) {
	t.Helper()
	parentKey, parentSigner := makeSigningKey(t, parentZone)
	childKey, _ := makeSigningKey(t, childZone)
	ds := childKey.ToDS(dns.SHA256)
	rrset := RRset{
		Name:    dns.Fqdn(childZone),
		Class:   dns.ClassINET,
		Type:    dns.TypeDS,
		Records: []dns.RR{ds},
	}
	signature := &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: dns.Fqdn(childZone), Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		Algorithm:  dns.ED25519,
		Expiration: uint32(at.Add(time.Hour).Unix()),
		Inception:  uint32(at.Add(-time.Hour).Unix()),
		KeyTag:     parentKey.KeyTag(),
		SignerName: dns.Fqdn(parentZone),
	}
	if err := signature.Sign(parentSigner, rrset.Records); err != nil {
		t.Fatalf("RRSIG.Sign(): %v", err)
	}
	return rrset, signature, parentKey, childKey, parentSigner
}

func TestValidateDelegationDSAcceptsAuthenticatedDelegation(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, parentKey, childKey, _ := signedDelegationDS(t, at)

	keys, err := ValidateDelegationDS(
		"test.",
		rrset,
		[]*dns.RRSIG{signature},
		[]*dns.DNSKEY{parentKey},
		[]*dns.DNSKEY{childKey},
		at,
	)
	if err != nil {
		t.Fatalf("ValidateDelegationDS() error = %v", err)
	}
	if len(keys) != 1 || !sameDNSKEY(keys[0], childKey) {
		t.Fatalf("matched keys = %v, want child DNSKEY", keys)
	}
}

func TestValidateDelegationDSRejectsInvalidParentSignature(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, parentKey, childKey, _ := signedDelegationDS(t, at)
	rrset.Records[0].(*dns.DS).Digest = strings.Repeat("0", len(rrset.Records[0].(*dns.DS).Digest))

	_, err := ValidateDelegationDS(
		"test.",
		rrset,
		[]*dns.RRSIG{signature},
		[]*dns.DNSKEY{parentKey},
		[]*dns.DNSKEY{childKey},
		at,
	)
	if !errors.Is(err, ErrNoValidSignature) {
		t.Fatalf("error = %v, want ErrNoValidSignature", err)
	}
}

func TestValidateDelegationDSRejectsChildKeyMismatch(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, parentKey, _, _ := signedDelegationDS(t, at)
	wrongChildKey, _ := makeSigningKey(t, "example.test.")

	_, err := ValidateDelegationDS(
		"test.",
		rrset,
		[]*dns.RRSIG{signature},
		[]*dns.DNSKEY{parentKey},
		[]*dns.DNSKEY{wrongChildKey},
		at,
	)
	if !errors.Is(err, ErrNoDelegationKey) {
		t.Fatalf("error = %v, want ErrNoDelegationKey", err)
	}
}

func TestValidateDelegationDSRejectsWrongParentZone(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, parentKey, childKey, _ := signedDelegationDS(t, at)

	_, err := ValidateDelegationDS(
		"other.",
		rrset,
		[]*dns.RRSIG{signature},
		[]*dns.DNSKEY{parentKey},
		[]*dns.DNSKEY{childKey},
		at,
	)
	if err == nil {
		t.Fatal("ValidateDelegationDS() error = nil, want invalid parent/child relationship")
	}
}

func TestValidateDelegationDSRejectsUnsupportedDigest(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, _, parentKey, childKey, parentSigner := signedDelegationDS(t, at)
	rrset.Records[0].(*dns.DS).DigestType = 250
	signature := &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		Algorithm:  dns.ED25519,
		Expiration: uint32(at.Add(time.Hour).Unix()),
		Inception:  uint32(at.Add(-time.Hour).Unix()),
		KeyTag:     parentKey.KeyTag(),
		SignerName: "test.",
	}
	if err := signature.Sign(parentSigner, rrset.Records); err != nil {
		t.Fatalf("RRSIG.Sign(): %v", err)
	}

	_, err := ValidateDelegationDS(
		"test.",
		rrset,
		[]*dns.RRSIG{signature},
		[]*dns.DNSKEY{parentKey},
		[]*dns.DNSKEY{childKey},
		at,
	)
	if !errors.Is(err, ErrUnsupportedDigest) {
		t.Fatalf("error = %v, want ErrUnsupportedDigest", err)
	}
}

func TestValidateDelegationDSIgnoresNonProtocolThreeKeys(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	parentKey, parentSigner := makeSigningKey(t, "test.")
	invalidParent := *parentKey
	invalidParent.Protocol = 2
	childKey, _ := makeSigningKey(t, "example.test.")
	invalidChild := *childKey
	invalidChild.Protocol = 2
	dsSet := RRset{
		Name: "example.test.", Class: dns.ClassINET, Type: dns.TypeDS,
		Records: []dns.RR{childKey.ToDS(dns.SHA256)},
	}
	dsSignature := signTestRRset(t, dsSet, parentKey, parentSigner, at)

	matched, err := ValidateDelegationDS(
		"test.", dsSet, []*dns.RRSIG{dsSignature},
		[]*dns.DNSKEY{&invalidParent, parentKey},
		[]*dns.DNSKEY{&invalidChild, childKey}, at,
	)
	if err != nil {
		t.Fatalf("ValidateDelegationDS() error = %v", err)
	}
	if len(matched) != 1 || !sameDNSKEY(matched[0], childKey) {
		t.Fatalf("matched keys = %d, want only valid protocol-3 child key", len(matched))
	}
}

func TestValidateDelegationDSPrefersSHA256OverSHA1ForSameKey(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	parentKey, parentSigner := makeSigningKey(t, "test.")
	childKey, _ := makeSigningKey(t, "example.test.")
	dsSet := RRset{Name: "example.test.", Class: dns.ClassINET, Type: dns.TypeDS,
		Records: []dns.RR{childKey.ToDS(dns.SHA1), childKey.ToDS(dns.SHA256)}}
	signature := signTestRRset(t, dsSet, parentKey, parentSigner, at)
	matched, err := ValidateDelegationDS("test.", dsSet, []*dns.RRSIG{signature},
		[]*dns.DNSKEY{parentKey}, []*dns.DNSKEY{childKey}, at)
	if err != nil {
		t.Fatalf("ValidateDelegationDS() error = %v", err)
	}
	if len(matched) != 1 || !sameDNSKEY(matched[0], childKey) {
		t.Fatalf("matched keys = %d, want SHA-256 match for same key", len(matched))
	}
}

func TestValidateDelegationDSPreservesSHA1ForDifferentKey(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	parentKey, parentSigner := makeSigningKey(t, "test.")
	sha1Child, _ := makeSigningKey(t, "example.test.")
	sha256Child, _ := makeSigningKey(t, "example.test.")
	dsSet := RRset{Name: "example.test.", Class: dns.ClassINET, Type: dns.TypeDS,
		Records: []dns.RR{sha1Child.ToDS(dns.SHA1), sha256Child.ToDS(dns.SHA256)}}
	signature := signTestRRset(t, dsSet, parentKey, parentSigner, at)
	matched, err := ValidateDelegationDS("test.", dsSet, []*dns.RRSIG{signature},
		[]*dns.DNSKEY{parentKey}, []*dns.DNSKEY{sha1Child, sha256Child}, at)
	if err != nil {
		t.Fatalf("ValidateDelegationDS() error = %v", err)
	}
	if len(matched) != 2 {
		t.Fatalf("matched keys = %d, want both distinct keys", len(matched))
	}
}

func TestValidateDelegationDSAcceptsSHA1WhenSHA256IsAbsent(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	parentKey, parentSigner := makeSigningKey(t, "test.")
	childKey, _ := makeSigningKey(t, "example.test.")
	dsSet := RRset{Name: "example.test.", Class: dns.ClassINET, Type: dns.TypeDS, Records: []dns.RR{childKey.ToDS(dns.SHA1)}}
	dsSignature := signTestRRset(t, dsSet, parentKey, parentSigner, at)
	matched, err := ValidateDelegationDS("test.", dsSet, []*dns.RRSIG{dsSignature}, []*dns.DNSKEY{parentKey}, []*dns.DNSKEY{childKey}, at)
	if err != nil {
		t.Fatalf("ValidateDelegationDS() error = %v", err)
	}
	if len(matched) != 1 || !sameDNSKEY(matched[0], childKey) {
		t.Fatalf("matched keys = %d, want SHA-1 legacy match", len(matched))
	}
}

func TestIsChildZoneAcceptsDescendants(t *testing.T) {
	tests := []struct {
		name   string
		parent string
		child  string
		want   bool
	}{
		{"immediate child", "example.test.", "child.example.test.", true},
		{"grandchild", "example.test.", "grandchild.child.example.test.", true},
		{"deep descendant", "example.test.", "a.b.c.example.test.", true},
		{"same zone", "example.test.", "example.test.", false},
		{"unrelated zone", "example.test.", "example.org.", false},
		{"root direct child", ".", "test.", true},
		{"root multi-label descendant", ".", "child.test.", true},
		{"root itself", ".", ".", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isChildZone(tt.parent, tt.child)
			if got != tt.want {
				t.Fatalf("isChildZone(%q, %q) = %t, want %t", tt.parent, tt.child, got, tt.want)
			}
		})
	}
}

func TestValidateDelegationDSAcceptsDeepDescendantDelegation(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	const parentZone = "example.test."
	const childZone = "www.dept.example.test."
	rrset, signature, parentKey, childKey, _ := signedDelegationDSForZones(
		t, at, parentZone, childZone,
	)

	keys, err := ValidateDelegationDS(
		parentZone,
		rrset,
		[]*dns.RRSIG{signature},
		[]*dns.DNSKEY{parentKey},
		[]*dns.DNSKEY{childKey},
		at,
	)
	if err != nil {
		t.Fatalf("ValidateDelegationDS() rejected a valid descendant delegation: %v", err)
	}
	if len(keys) != 1 || !sameDNSKEY(keys[0], childKey) {
		t.Fatalf("matched keys = %v, want child DNSKEY", keys)
	}
}
