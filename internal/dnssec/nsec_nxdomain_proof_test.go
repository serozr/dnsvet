package dnssec

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestValidateNSECNXDOMAINProofSingleNSECSuccess(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	const zone = "example.test."
	key, signer := makeSigningKey(t, zone)

	// Single NSEC in zone wrapping from apex to apex (single-record zone)
	// It covers every name in the zone, including missing.example.test. and *.example.test.
	nsec := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: zone, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600},
		NextDomain: zone,
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY},
	}
	rrset := RRset{Name: zone, Class: dns.ClassINET, Type: dns.TypeNSEC, Records: []dns.RR{nsec}}
	sig := signTestRRset(t, rrset, key, signer, at)

	res := ValidateNSECNXDOMAINProof(
		zone,
		"missing.example.test.",
		[]RRset{rrset},
		[][]*dns.RRSIG{{sig}},
		[]*dns.DNSKEY{key},
		at,
	)
	if res.Status != NSECProofProven {
		t.Fatalf("expected NSECProofProven, got status=%s, reason=%s", res.Status, res.Reason)
	}
}

func TestValidateNSECNXDOMAINProofTwoNSECsSuccess(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	const zone = "example.test."
	key, signer := makeSigningKey(t, zone)

	// In canonical DNS order:
	// 1. example.test. (apex)
	// 2. *.example.test. (wire: 0x2A)
	// 3. a.example.test. (wire: 0x61)
	// 4. missing.example.test. (wire: 0x6D)
	// 5. z.example.test. (wire: 0x7A)
	//
	// NSEC 1: example.test. -> a.example.test. covers *.example.test.
	// NSEC 2: a.example.test. -> z.example.test. covers missing.example.test.

	nsec1 := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: zone, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600},
		NextDomain: "a.example.test.",
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC},
	}
	rrset1 := RRset{Name: zone, Class: dns.ClassINET, Type: dns.TypeNSEC, Records: []dns.RR{nsec1}}
	sig1 := signTestRRset(t, rrset1, key, signer, at)

	nsec2 := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "a.example.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600},
		NextDomain: "z.example.test.",
		TypeBitMap: []uint16{dns.TypeA, dns.TypeNSEC, dns.TypeRRSIG},
	}
	rrset2 := RRset{Name: "a.example.test.", Class: dns.ClassINET, Type: dns.TypeNSEC, Records: []dns.RR{nsec2}}
	sig2 := signTestRRset(t, rrset2, key, signer, at)

	res := ValidateNSECNXDOMAINProof(
		zone,
		"missing.example.test.",
		[]RRset{rrset1, rrset2},
		[][]*dns.RRSIG{{sig1}, {sig2}},
		[]*dns.DNSKEY{key},
		at,
	)
	if res.Status != NSECProofProven {
		t.Fatalf("expected NSECProofProven, got status=%s, reason=%s", res.Status, res.Reason)
	}
}

func TestValidateNSECNXDOMAINProofRejectsMissingWildcardDenial(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	const zone = "example.test."
	key, signer := makeSigningKey(t, zone)

	// Only NSEC 2 is provided, which covers missing.example.test., but not *.example.test.
	nsec2 := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "a.example.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600},
		NextDomain: "z.example.test.",
		TypeBitMap: []uint16{dns.TypeA, dns.TypeNSEC, dns.TypeRRSIG},
	}
	rrset2 := RRset{Name: "a.example.test.", Class: dns.ClassINET, Type: dns.TypeNSEC, Records: []dns.RR{nsec2}}
	sig2 := signTestRRset(t, rrset2, key, signer, at)

	res := ValidateNSECNXDOMAINProof(
		zone,
		"missing.example.test.",
		[]RRset{rrset2},
		[][]*dns.RRSIG{{sig2}},
		[]*dns.DNSKEY{key},
		at,
	)
	if res.Status != NSECProofNotProven {
		t.Fatalf("expected NSECProofNotProven due to missing wildcard denial, got %s", res.Status)
	}
}

func TestValidateNSECNXDOMAINProofRejectsContradictoryQName(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	const zone = "example.test."
	key, signer := makeSigningKey(t, zone)

	// An NSEC whose owner matches QNAME is passed (QNAME actually exists!)
	nsec := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "existing.example.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600},
		NextDomain: "z.example.test.",
		TypeBitMap: []uint16{dns.TypeA, dns.TypeNSEC, dns.TypeRRSIG},
	}
	rrset := RRset{Name: "existing.example.test.", Class: dns.ClassINET, Type: dns.TypeNSEC, Records: []dns.RR{nsec}}
	sig := signTestRRset(t, rrset, key, signer, at)

	res := ValidateNSECNXDOMAINProof(
		zone,
		"existing.example.test.",
		[]RRset{rrset},
		[][]*dns.RRSIG{{sig}},
		[]*dns.DNSKEY{key},
		at,
	)
	if res.Status != NSECProofInvalid {
		t.Fatalf("expected NSECProofInvalid for contradictory existing owner, got %s", res.Status)
	}
}

func TestValidateNSECNXDOMAINProofRejectsContradictoryWildcard(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	const zone = "example.test."
	key, signer := makeSigningKey(t, zone)

	// NSEC for *.example.test. exists! (Wildcard exists in zone)
	nsecWild := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "*.example.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600},
		NextDomain: "z.example.test.",
		TypeBitMap: []uint16{dns.TypeTXT, dns.TypeNSEC, dns.TypeRRSIG},
	}
	rrsetWild := RRset{Name: "*.example.test.", Class: dns.ClassINET, Type: dns.TypeNSEC, Records: []dns.RR{nsecWild}}
	sigWild := signTestRRset(t, rrsetWild, key, signer, at)

	res := ValidateNSECNXDOMAINProof(
		zone,
		"missing.example.test.",
		[]RRset{rrsetWild},
		[][]*dns.RRSIG{{sigWild}},
		[]*dns.DNSKEY{key},
		at,
	)
	if res.Status != NSECProofInvalid {
		t.Fatalf("expected NSECProofInvalid when wildcard exists, got %s", res.Status)
	}
}
