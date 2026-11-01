package dnssec

import (
	"crypto"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestValidateChainWithNoDelegationsReturnsAnchorZone(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, key := signedDNSKEYSet(t, at)

	result, err := ValidateChain(
		TrustAnchor{Zone: "example.test.", DNSKEY: key},
		rrset,
		[]*dns.RRSIG{signature},
		nil,
		at,
	)
	if err != nil {
		t.Fatalf("ValidateChain() error = %v", err)
	}
	if result.Zone != "example.test." || len(result.Keys) != 1 || !sameDNSKEY(result.Keys[0], key) {
		t.Fatalf("unexpected chain result: zone=%q keys=%d", result.Zone, len(result.Keys))
	}
}

func TestValidateChainAuthenticatesDelegation(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	anchorKey, anchorSigner := makeSigningKey(t, "example.test.")
	anchorSet := RRset{
		Name:    "example.test.",
		Class:   dns.ClassINET,
		Type:    dns.TypeDNSKEY,
		Records: []dns.RR{anchorKey},
	}
	anchorSig := signTestRRset(t, anchorSet, anchorKey, anchorSigner, at)

	childKey, childSigner := makeSigningKey(t, "child.example.test.")
	childSet := RRset{
		Name:    "child.example.test.",
		Class:   dns.ClassINET,
		Type:    dns.TypeDNSKEY,
		Records: []dns.RR{childKey},
	}
	childSig := signTestRRset(t, childSet, childKey, childSigner, at)

	dsSet := RRset{
		Name:    "child.example.test.",
		Class:   dns.ClassINET,
		Type:    dns.TypeDS,
		Records: []dns.RR{childKey.ToDS(dns.SHA256)},
	}
	dsSig := signTestRRset(t, dsSet, anchorKey, anchorSigner, at)

	result, err := ValidateChain(
		TrustAnchor{Zone: "example.test.", DNSKEY: anchorKey},
		anchorSet,
		[]*dns.RRSIG{anchorSig},
		[]Delegation{{
			DSRRset:          dsSet,
			DSSignatures:     []*dns.RRSIG{dsSig},
			DNSKEYRRset:      childSet,
			DNSKEYSignatures: []*dns.RRSIG{childSig},
		}},
		at,
	)
	if err != nil {
		t.Fatalf("ValidateChain() error = %v", err)
	}
	if result.Zone != "child.example.test." || len(result.Keys) != 1 || !sameDNSKEY(result.Keys[0], childKey) {
		t.Fatalf("unexpected chain result: zone=%q keys=%d", result.Zone, len(result.Keys))
	}
}

func TestValidateChainRejectsTamperedChildDNSKEYSet(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	anchorKey, anchorSigner := makeSigningKey(t, "example.test.")
	anchorSet := RRset{
		Name:    "example.test.",
		Class:   dns.ClassINET,
		Type:    dns.TypeDNSKEY,
		Records: []dns.RR{anchorKey},
	}
	anchorSig := signTestRRset(t, anchorSet, anchorKey, anchorSigner, at)

	childKey, childSigner := makeSigningKey(t, "child.example.test.")
	additionalKey, _ := makeSigningKey(t, "child.example.test.")
	childSet := RRset{
		Name:    "child.example.test.",
		Class:   dns.ClassINET,
		Type:    dns.TypeDNSKEY,
		Records: []dns.RR{childKey, additionalKey},
	}
	childSig := signTestRRset(t, childSet, childKey, childSigner, at)
	dsSet := RRset{
		Name:    "child.example.test.",
		Class:   dns.ClassINET,
		Type:    dns.TypeDS,
		Records: []dns.RR{childKey.ToDS(dns.SHA256)},
	}
	dsSig := signTestRRset(t, dsSet, anchorKey, anchorSigner, at)
	childSet.Records[1].(*dns.DNSKEY).PublicKey += "A"

	_, err := ValidateChain(
		TrustAnchor{Zone: "example.test.", DNSKEY: anchorKey},
		anchorSet,
		[]*dns.RRSIG{anchorSig},
		[]Delegation{{
			DSRRset:          dsSet,
			DSSignatures:     []*dns.RRSIG{dsSig},
			DNSKEYRRset:      childSet,
			DNSKEYSignatures: []*dns.RRSIG{childSig},
		}},
		at,
	)
	if !errors.Is(err, ErrNoValidSignature) {
		t.Fatalf("error = %v, want ErrNoValidSignature", err)
	}
}

func TestValidateChainRejectsExcessiveDepth(t *testing.T) {
	delegations := make([]Delegation, MaxDelegationDepth+1)
	_, err := ValidateChain(TrustAnchor{}, RRset{}, nil, delegations, time.Now())
	if err == nil {
		t.Fatal("ValidateChain() error = nil, want depth limit error")
	}
}

func TestValidateChainRejectsMismatchedDSAndDNSKEYOwners(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, key := signedDNSKEYSet(t, at)
	delegation := Delegation{
		DSRRset: RRset{
			Name: "child.example.test.",
			Type: dns.TypeDS,
		},
		DNSKEYRRset: RRset{
			Name: "other.example.test.",
			Type: dns.TypeDNSKEY,
		},
	}
	_, err := ValidateChain(
		TrustAnchor{Zone: "example.test.", DNSKEY: key},
		rrset,
		[]*dns.RRSIG{signature},
		[]Delegation{delegation},
		at,
	)
	if err == nil {
		t.Fatal("ValidateChain() error = nil, want owner mismatch")
	}
}

func signTestRRset(t *testing.T, rrset RRset, key *dns.DNSKEY, signer crypto.Signer, at time.Time) *dns.RRSIG {
	t.Helper()
	sig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name: rrset.Name, Rrtype: dns.TypeRRSIG, Class: rrset.Class, Ttl: 3600,
		},
		Algorithm:  key.Algorithm,
		Expiration: uint32(at.Add(time.Hour).Unix()),
		Inception:  uint32(at.Add(-time.Hour).Unix()),
		KeyTag:     key.KeyTag(),
		SignerName: key.Hdr.Name,
	}
	if err := sig.Sign(signer, rrset.Records); err != nil {
		t.Fatalf("RRSIG.Sign(): %v", err)
	}
	return sig
}

func TestValidateChainAuthenticatesMultipleDelegationLevels(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

	anchorKey, anchorSigner := makeSigningKey(t, "example.test.")
	anchorSet := RRset{
		Name: "example.test.", Class: dns.ClassINET, Type: dns.TypeDNSKEY,
		Records: []dns.RR{anchorKey},
	}
	anchorSig := signTestRRset(t, anchorSet, anchorKey, anchorSigner, at)

	childKey, childSigner := makeSigningKey(t, "child.example.test.")
	childSet := RRset{
		Name: "child.example.test.", Class: dns.ClassINET, Type: dns.TypeDNSKEY,
		Records: []dns.RR{childKey},
	}
	childSig := signTestRRset(t, childSet, childKey, childSigner, at)
	childDSSet := RRset{
		Name: "child.example.test.", Class: dns.ClassINET, Type: dns.TypeDS,
		Records: []dns.RR{childKey.ToDS(dns.SHA256)},
	}
	childDSSig := signTestRRset(t, childDSSet, anchorKey, anchorSigner, at)

	grandchildKey, grandchildSigner := makeSigningKey(t, "grandchild.child.example.test.")
	grandchildSet := RRset{
		Name: "grandchild.child.example.test.", Class: dns.ClassINET, Type: dns.TypeDNSKEY,
		Records: []dns.RR{grandchildKey},
	}
	grandchildSig := signTestRRset(t, grandchildSet, grandchildKey, grandchildSigner, at)
	grandchildDSSet := RRset{
		Name: "grandchild.child.example.test.", Class: dns.ClassINET, Type: dns.TypeDS,
		Records: []dns.RR{grandchildKey.ToDS(dns.SHA256)},
	}
	grandchildDSSig := signTestRRset(t, grandchildDSSet, childKey, childSigner, at)

	result, err := ValidateChain(
		TrustAnchor{Zone: "example.test.", DNSKEY: anchorKey},
		anchorSet,
		[]*dns.RRSIG{anchorSig},
		[]Delegation{
			{
				DSRRset: childDSSet, DSSignatures: []*dns.RRSIG{childDSSig},
				DNSKEYRRset: childSet, DNSKEYSignatures: []*dns.RRSIG{childSig},
			},
			{
				DSRRset: grandchildDSSet, DSSignatures: []*dns.RRSIG{grandchildDSSig},
				DNSKEYRRset: grandchildSet, DNSKEYSignatures: []*dns.RRSIG{grandchildSig},
			},
		},
		at,
	)
	if err != nil {
		t.Fatalf("ValidateChain() error = %v", err)
	}
	if result.Zone != "grandchild.child.example.test." || len(result.Keys) != 1 ||
		!sameDNSKEY(result.Keys[0], grandchildKey) {
		t.Fatalf("unexpected chain result: zone=%q keys=%d", result.Zone, len(result.Keys))
	}
}

func TestValidateChainRejectsInvalidSecondLevelDelegationSignature(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

	anchorKey, anchorSigner := makeSigningKey(t, "example.test.")
	anchorSet := RRset{
		Name: "example.test.", Class: dns.ClassINET, Type: dns.TypeDNSKEY,
		Records: []dns.RR{anchorKey},
	}
	anchorSig := signTestRRset(t, anchorSet, anchorKey, anchorSigner, at)

	childKey, childSigner := makeSigningKey(t, "child.example.test.")
	childSet := RRset{
		Name: "child.example.test.", Class: dns.ClassINET, Type: dns.TypeDNSKEY,
		Records: []dns.RR{childKey},
	}
	childSig := signTestRRset(t, childSet, childKey, childSigner, at)
	childDSSet := RRset{
		Name: "child.example.test.", Class: dns.ClassINET, Type: dns.TypeDS,
		Records: []dns.RR{childKey.ToDS(dns.SHA256)},
	}
	childDSSig := signTestRRset(t, childDSSet, anchorKey, anchorSigner, at)

	grandchildKey, grandchildSigner := makeSigningKey(t, "grandchild.child.example.test.")
	grandchildSet := RRset{
		Name: "grandchild.child.example.test.", Class: dns.ClassINET, Type: dns.TypeDNSKEY,
		Records: []dns.RR{grandchildKey},
	}
	grandchildSig := signTestRRset(t, grandchildSet, grandchildKey, grandchildSigner, at)
	grandchildDSSet := RRset{
		Name: "grandchild.child.example.test.", Class: dns.ClassINET, Type: dns.TypeDS,
		Records: []dns.RR{grandchildKey.ToDS(dns.SHA256)},
	}
	// Deliberately sign the second DS RRset with the root anchor, not its parent.
	invalidGrandchildDSSig := signTestRRset(t, grandchildDSSet, anchorKey, anchorSigner, at)

	_, err := ValidateChain(
		TrustAnchor{Zone: "example.test.", DNSKEY: anchorKey},
		anchorSet,
		[]*dns.RRSIG{anchorSig},
		[]Delegation{
			{
				DSRRset: childDSSet, DSSignatures: []*dns.RRSIG{childDSSig},
				DNSKEYRRset: childSet, DNSKEYSignatures: []*dns.RRSIG{childSig},
			},
			{
				DSRRset: grandchildDSSet, DSSignatures: []*dns.RRSIG{invalidGrandchildDSSig},
				DNSKEYRRset: grandchildSet, DNSKEYSignatures: []*dns.RRSIG{grandchildSig},
			},
		},
		at,
	)
	if !errors.Is(err, ErrNoMatchingKey) {
		t.Fatalf("error = %v, want ErrNoMatchingKey", err)
	}
}

func TestValidateChainRejectsMalformedDelegationOwner(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	anchorRRset, anchorSignature, anchorKey := signedDNSKEYSet(t, at)
	delegation := Delegation{
		DSRRset: RRset{
			Name: "bad..child.example.test.", Class: dns.ClassINET, Type: dns.TypeDS,
		},
		DNSKEYRRset: RRset{
			Name: "bad..child.example.test.", Class: dns.ClassINET, Type: dns.TypeDNSKEY,
		},
	}

	_, err := ValidateChain(
		TrustAnchor{Zone: "example.test.", DNSKEY: anchorKey},
		anchorRRset,
		[]*dns.RRSIG{anchorSignature},
		[]Delegation{delegation},
		at,
	)
	if err == nil {
		t.Fatal("ValidateChain() error = nil, want malformed DNS owner rejection")
	}
}

func TestValidateChainRejectsMalformedTrustAnchorZone(t *testing.T) {
	_, err := ValidateChain(
		TrustAnchor{Zone: "bad..example.test."},
		RRset{},
		nil,
		nil,
		time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
	)
	if err == nil {
		t.Fatal("ValidateChain() error = nil, want malformed trust anchor rejection")
	}
}

func TestValidateChainAcceptsMultipleTrustAnchorsEndToEnd(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	firstKey, _ := makeSigningKey(t, "example.test.")
	secondKey, secondSigner := makeSigningKey(t, "example.test.")
	anchorSet := RRset{
		Name:    "example.test.",
		Class:   dns.ClassINET,
		Type:    dns.TypeDNSKEY,
		Records: []dns.RR{firstKey, secondKey},
	}
	anchorSignature := signTestRRset(t, anchorSet, secondKey, secondSigner, at)

	result, err := ValidateChain(
		TrustAnchor{
			Zone:    "example.test.",
			DNSKEYs: []*dns.DNSKEY{firstKey, secondKey},
		},
		anchorSet,
		[]*dns.RRSIG{anchorSignature},
		nil,
		at,
	)
	if err != nil {
		t.Fatalf("ValidateChain() with multiple trust anchors error = %v", err)
	}
	if result.Zone != "example.test." {
		t.Fatalf("result zone = %q, want example.test.", result.Zone)
	}
	if len(result.Keys) != 2 ||
		!containsDNSKEY(result.Keys, firstKey) ||
		!containsDNSKEY(result.Keys, secondKey) {
		t.Fatalf("authenticated keys = %d, want both configured DNSKEYs", len(result.Keys))
	}
}
