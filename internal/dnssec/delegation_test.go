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
	t.Helper()
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
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
	return key, signer
}

func signedDelegationDS(t *testing.T, at time.Time) (RRset, *dns.RRSIG, *dns.DNSKEY, *dns.DNSKEY, crypto.Signer) {
	t.Helper()
	parentKey, parentSigner := makeSigningKey(t, "test.")
	childKey, _ := makeSigningKey(t, "example.test.")
	ds := childKey.ToDS(dns.SHA256)
	rrset := RRset{
		Name:    "example.test.",
		Class:   dns.ClassINET,
		Type:    dns.TypeDS,
		Records: []dns.RR{ds},
	}
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
