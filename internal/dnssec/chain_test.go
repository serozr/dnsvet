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
