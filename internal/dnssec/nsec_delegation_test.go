package dnssec

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func signedDelegationNSEC(t *testing.T, at time.Time, bitmap []uint16) (RRset, *dns.RRSIG, *dns.DNSKEY) {
	return signedDelegationNSECWithNext(t, at, bitmap, "next.example.test.")
}

func signedDelegationNSECWithNext(t *testing.T, at time.Time, bitmap []uint16, next string) (RRset, *dns.RRSIG, *dns.DNSKEY) {
	t.Helper()
	parentKey, parentSigner := makeSigningKey(t, "example.test.")
	nsec := &dns.NSEC{
		Hdr: dns.RR_Header{
			Name: "child.example.test.", Rrtype: dns.TypeNSEC,
			Class: dns.ClassINET, Ttl: 3600,
		},
		NextDomain: next,
		TypeBitMap: bitmap,
	}
	rrset := RRset{Name: nsec.Hdr.Name, Class: dns.ClassINET, Type: dns.TypeNSEC, Records: []dns.RR{nsec}}
	signature := &dns.RRSIG{
		Hdr: dns.RR_Header{Name: nsec.Hdr.Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		Algorithm:  parentKey.Algorithm,
		Expiration: uint32(at.Add(time.Hour).Unix()),
		Inception:  uint32(at.Add(-time.Hour).Unix()),
		KeyTag:     parentKey.KeyTag(),
		SignerName: "example.test.",
	}
	if err := signature.Sign(parentSigner, rrset.Records); err != nil {
		t.Fatalf("RRSIG.Sign(): %v", err)
	}
	return rrset, signature, parentKey
}

func TestValidateInsecureDelegationNSECProvesDSAbsence(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, parentKey := signedDelegationNSEC(t, at, []uint16{dns.TypeNS, dns.TypeNSEC, dns.TypeRRSIG})
	result := ValidateInsecureDelegationNSEC("example.test.", "child.example.test.", rrset, []*dns.RRSIG{signature}, []*dns.DNSKEY{parentKey}, at)
	if result.Status != NSECProofProven {
		t.Fatalf("status = %q, reason = %q; want proven", result.Status, result.Reason)
	}
}

func TestValidateInsecureDelegationNSECDoesNotProveWhenDSPresent(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, parentKey := signedDelegationNSEC(t, at, []uint16{dns.TypeNS, dns.TypeDS})
	result := ValidateInsecureDelegationNSEC("example.test.", "child.example.test.", rrset, []*dns.RRSIG{signature}, []*dns.DNSKEY{parentKey}, at)
	if result.Status != NSECProofNotProven {
		t.Fatalf("status = %q, want not_proven", result.Status)
	}
}

func TestValidateInsecureDelegationNSECRejectsWrongOwner(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, parentKey := signedDelegationNSEC(t, at, []uint16{dns.TypeNS})
	result := ValidateInsecureDelegationNSEC("example.test.", "other.example.test.", rrset, []*dns.RRSIG{signature}, []*dns.DNSKEY{parentKey}, at)
	if result.Status != NSECProofInvalid {
		t.Fatalf("status = %q, want invalid", result.Status)
	}
}

func TestValidateInsecureDelegationNSECRejectsInvalidSignature(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, parentKey := signedDelegationNSEC(t, at, []uint16{dns.TypeNS})
	rrset.Records[0].(*dns.NSEC).NextDomain = "tampered.example.test."
	result := ValidateInsecureDelegationNSEC("example.test.", "child.example.test.", rrset, []*dns.RRSIG{signature}, []*dns.DNSKEY{parentKey}, at)
	if result.Status != NSECProofInvalid {
		t.Fatalf("status = %q, want invalid", result.Status)
	}
}

func TestValidateInsecureDelegationNSECRequiresAuthenticatedParentKeys(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, _ := signedDelegationNSEC(t, at, []uint16{dns.TypeNS})
	result := ValidateInsecureDelegationNSEC("example.test.", "child.example.test.", rrset, []*dns.RRSIG{signature}, nil, at)
	if result.Status != NSECProofNotProven {
		t.Fatalf("status = %q, want not_proven", result.Status)
	}
}

func TestValidateInsecureDelegationNSECRejectsOutOfZoneNextDomain(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, parentKey := signedDelegationNSEC(t, at, []uint16{dns.TypeNS})
	rrset.Records[0].(*dns.NSEC).NextDomain = "outside.invalid."
	result := ValidateInsecureDelegationNSEC("example.test.", "child.example.test.", rrset, []*dns.RRSIG{signature}, []*dns.DNSKEY{parentKey}, at)
	if result.Status != NSECProofInvalid {
		t.Fatalf("status = %q, want invalid", result.Status)
	}
}

func TestValidateInsecureDelegationNSECAllowsWrapAroundToApex(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, parentKey := signedDelegationNSECWithNext(t, at, []uint16{dns.TypeNS}, "example.test.")
	result := ValidateInsecureDelegationNSEC("example.test.", "child.example.test.", rrset, []*dns.RRSIG{signature}, []*dns.DNSKEY{parentKey}, at)
	if result.Status != NSECProofProven {
		t.Fatalf("status = %q, reason = %q; want proven", result.Status, result.Reason)
	}
}

func TestValidateInsecureDelegationNSECRejectsSOABitmap(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, parentKey := signedDelegationNSEC(t, at, []uint16{dns.TypeNS, dns.TypeSOA})
	result := ValidateInsecureDelegationNSEC("example.test.", "child.example.test.", rrset, []*dns.RRSIG{signature}, []*dns.DNSKEY{parentKey}, at)
	if result.Status != NSECProofInvalid {
		t.Fatalf("status = %q, want invalid", result.Status)
	}
}
