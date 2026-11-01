package dnssec

import (
	"crypto"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func signedNSECIntervalFixture(t *testing.T, owner, next, zone string) (RRset, *dns.RRSIG, *dns.DNSKEY, time.Time) {
	return signedNSECIntervalFixtureWithBitmap(t, owner, next, zone, []uint16{dns.TypeA})
}

func signedNSECIntervalFixtureWithBitmap(t *testing.T, owner, next, zone string, bitmap []uint16) (RRset, *dns.RRSIG, *dns.DNSKEY, time.Time) {
	t.Helper()
	at := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
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
	record := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: next,
		TypeBitMap: bitmap,
	}
	rrset := RRset{
		Name:    owner,
		Class:   dns.ClassINET,
		Type:    dns.TypeNSEC,
		Records: []dns.RR{record},
	}
	signature := &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		Algorithm:  dns.ED25519,
		Expiration: uint32(at.Add(time.Hour).Unix()),
		Inception:  uint32(at.Add(-time.Hour).Unix()),
		KeyTag:     key.KeyTag(),
		SignerName: zone,
	}
	if err := signature.Sign(signer, rrset.Records); err != nil {
		t.Fatalf("RRSIG.Sign(): %v", err)
	}
	return rrset, signature, key, at
}

func TestValidateNSECIntervalProof(t *testing.T) {
	tests := []struct {
		name  string
		owner string
		next  string
		query string
		want  NSECProofStatus
	}{
		{"normal interval", "a.example.", "z.example.", "m.example.", NSECProofProven},
		{"wrap around after owner", "z.example.", "a.example.", "zz.example.", NSECProofProven},
		{"wrap around before next", "z.example.", "a.example.", "0.example.", NSECProofProven},
		{"outside interval", "a.example.", "z.example.", "0.example.", NSECProofNotProven},
		{"owner endpoint", "a.example.", "z.example.", "a.example.", NSECProofNotProven},
		{"next endpoint", "a.example.", "z.example.", "z.example.", NSECProofNotProven},
		{"single record zone", "example.", "example.", "www.example.", NSECProofProven},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rrset, signature, key, at := signedNSECIntervalFixture(t, tt.owner, tt.next, "example.")
			got := ValidateNSECIntervalProof("example.", tt.query, rrset, []*dns.RRSIG{signature}, []*dns.DNSKEY{key}, at)
			if got.Status != tt.want {
				t.Fatalf("status = %q, want %q (reason: %s)", got.Status, tt.want, got.Reason)
			}
		})
	}
}

func TestValidateNSECIntervalProofRejectsInvalidMaterial(t *testing.T) {
	t.Run("query outside zone", func(t *testing.T) {
		rrset, sig, key, at := signedNSECIntervalFixture(t, "a.example.", "z.example.", "example.")
		got := ValidateNSECIntervalProof("example.", "www.other.", rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{key}, at)
		if got.Status != NSECProofInvalid {
			t.Fatalf("status = %q, want invalid", got.Status)
		}
	})
	t.Run("next domain outside zone", func(t *testing.T) {
		rrset, sig, key, at := signedNSECIntervalFixture(t, "a.example.", "z.other.", "example.")
		got := ValidateNSECIntervalProof("example.", "m.example.", rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{key}, at)
		if got.Status != NSECProofInvalid {
			t.Fatalf("status = %q, want invalid", got.Status)
		}
	})
	t.Run("wrong signer", func(t *testing.T) {
		rrset, sig, key, at := signedNSECIntervalFixture(t, "a.example.", "z.example.", "example.")
		sig.SignerName = "other."
		got := ValidateNSECIntervalProof("example.", "m.example.", rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{key}, at)
		if got.Status != NSECProofInvalid {
			t.Fatalf("status = %q, want invalid", got.Status)
		}
	})
	t.Run("tampered NSEC after signing", func(t *testing.T) {
		rrset, sig, key, at := signedNSECIntervalFixture(t, "a.example.", "z.example.", "example.")
		rrset.Records[0].(*dns.NSEC).NextDomain = "y.example."
		got := ValidateNSECIntervalProof("example.", "m.example.", rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{key}, at)
		if got.Status != NSECProofInvalid {
			t.Fatalf("status = %q, want invalid", got.Status)
		}
	})
	t.Run("wrong RRset type", func(t *testing.T) {
		rrset, sig, key, at := signedNSECIntervalFixture(t, "a.example.", "z.example.", "example.")
		rrset.Type = dns.TypeA
		got := ValidateNSECIntervalProof("example.", "m.example.", rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{key}, at)
		if got.Status != NSECProofInvalid {
			t.Fatalf("status = %q, want invalid", got.Status)
		}
	})
	t.Run("no authenticated keys", func(t *testing.T) {
		rrset, sig, _, at := signedNSECIntervalFixture(t, "a.example.", "z.example.", "example.")
		got := ValidateNSECIntervalProof("example.", "m.example.", rrset, []*dns.RRSIG{sig}, nil, at)
		if got.Status != NSECProofNotProven {
			t.Fatalf("status = %q, want not_proven", got.Status)
		}
	})
}

func TestValidateNSECIntervalProofDelegationPointSafety(t *testing.T) {
	t.Run("does not prove below delegation point", func(t *testing.T) {
		rrset, sig, key, at := signedNSECIntervalFixtureWithBitmap(
			t, "child.example.", "z.example.", "example.", []uint16{dns.TypeNS},
		)
		got := ValidateNSECIntervalProof("example.", "host.child.example.", rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{key}, at)
		if got.Status != NSECProofNotProven {
			t.Fatalf("status = %q, want not_proven (reason: %s)", got.Status, got.Reason)
		}
	})
	t.Run("zone apex NS and SOA is not a delegation point", func(t *testing.T) {
		rrset, sig, key, at := signedNSECIntervalFixtureWithBitmap(
			t, "example.", "z.example.", "example.", []uint16{dns.TypeNS, dns.TypeSOA},
		)
		got := ValidateNSECIntervalProof("example.", "www.example.", rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{key}, at)
		if got.Status != NSECProofProven {
			t.Fatalf("status = %q, want proven (reason: %s)", got.Status, got.Reason)
		}
	})
}
