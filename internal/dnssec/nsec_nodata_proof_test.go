package dnssec

import (
	"crypto"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func signedNSECNoDataFixture(t *testing.T, owner string, bitmap []uint16) (RRset, *dns.RRSIG, *dns.DNSKEY, time.Time) {
	t.Helper()
	at := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
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
		NextDomain: "z.example.",
		TypeBitMap: append([]uint16(nil), bitmap...),
	}
	rrset := RRset{Name: owner, Class: dns.ClassINET, Type: dns.TypeNSEC, Records: []dns.RR{record}}
	signature := &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		Algorithm:  dns.ED25519,
		Expiration: uint32(at.Add(time.Hour).Unix()),
		Inception:  uint32(at.Add(-time.Hour).Unix()),
		KeyTag:     key.KeyTag(),
		SignerName: "example.",
	}
	if err := signature.Sign(signer, rrset.Records); err != nil {
		t.Fatalf("RRSIG.Sign(): %v", err)
	}
	return rrset, signature, key, at
}

func TestValidateNSECNoDataProof(t *testing.T) {
	tests := []struct {
		name   string
		qtype  uint16
		bitmap []uint16
		want   NSECProofStatus
	}{
		{"requested type absent", dns.TypeAAAA, []uint16{dns.TypeA}, NSECProofProven},
		{"requested type present", dns.TypeA, []uint16{dns.TypeA}, NSECProofNotProven},
		{"CNAME present", dns.TypeAAAA, []uint16{dns.TypeCNAME}, NSECProofNotProven},
		{"ANY unsupported", dns.TypeANY, []uint16{dns.TypeA}, NSECProofUnsupported},
		{"NSEC query unsupported", dns.TypeNSEC, []uint16{dns.TypeA}, NSECProofUnsupported},
		{"RRSIG query unsupported", dns.TypeRRSIG, []uint16{dns.TypeA}, NSECProofUnsupported},
		{"zero query type invalid", 0, []uint16{dns.TypeA}, NSECProofInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rrset, sig, key, at := signedNSECNoDataFixture(t, "www.example.", tt.bitmap)
			got := ValidateNSECNoDataProof("example.", "www.example.", tt.qtype, rrset,
				[]*dns.RRSIG{sig}, []*dns.DNSKEY{key}, at)
			if got.Status != tt.want {
				t.Fatalf("status = %q, want %q (reason: %s)", got.Status, tt.want, got.Reason)
			}
		})
	}
}

func TestValidateNSECNoDataProofRejectsUnsafeOrInvalidMaterial(t *testing.T) {
	t.Run("query name does not exactly match owner", func(t *testing.T) {
		rrset, sig, key, at := signedNSECNoDataFixture(t, "www.example.", []uint16{dns.TypeA})
		got := ValidateNSECNoDataProof("example.", "alias.example.", dns.TypeAAAA, rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{key}, at)
		if got.Status != NSECProofNotProven {
			t.Fatalf("status = %q, want not_proven", got.Status)
		}
	})
	t.Run("query outside zone", func(t *testing.T) {
		rrset, sig, key, at := signedNSECNoDataFixture(t, "www.example.", []uint16{dns.TypeA})
		got := ValidateNSECNoDataProof("example.", "www.other.", dns.TypeAAAA, rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{key}, at)
		if got.Status != NSECProofInvalid {
			t.Fatalf("status = %q, want invalid", got.Status)
		}
	})
	t.Run("delegation point rejected", func(t *testing.T) {
		rrset, sig, key, at := signedNSECNoDataFixture(t, "child.example.", []uint16{dns.TypeNS})
		got := ValidateNSECNoDataProof("example.", "child.example.", dns.TypeAAAA, rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{key}, at)
		if got.Status != NSECProofNotProven {
			t.Fatalf("status = %q, want not_proven", got.Status)
		}
	})
	t.Run("wrong signer rejected", func(t *testing.T) {
		rrset, sig, key, at := signedNSECNoDataFixture(t, "www.example.", []uint16{dns.TypeA})
		sig.SignerName = "other."
		got := ValidateNSECNoDataProof("example.", "www.example.", dns.TypeAAAA, rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{key}, at)
		if got.Status != NSECProofInvalid {
			t.Fatalf("status = %q, want invalid", got.Status)
		}
	})
	t.Run("no authenticated keys", func(t *testing.T) {
		rrset, sig, _, at := signedNSECNoDataFixture(t, "www.example.", []uint16{dns.TypeA})
		got := ValidateNSECNoDataProof("example.", "www.example.", dns.TypeAAAA, rrset, []*dns.RRSIG{sig}, nil, at)
		if got.Status != NSECProofNotProven {
			t.Fatalf("status = %q, want not_proven", got.Status)
		}
	})
	t.Run("tampered bitmap rejected by signature", func(t *testing.T) {
		rrset, sig, key, at := signedNSECNoDataFixture(t, "www.example.", []uint16{dns.TypeA})
		rrset.Records[0].(*dns.NSEC).TypeBitMap = []uint16{dns.TypeAAAA}
		got := ValidateNSECNoDataProof("example.", "www.example.", dns.TypeAAAA, rrset, []*dns.RRSIG{sig}, []*dns.DNSKEY{key}, at)
		if got.Status != NSECProofInvalid {
			t.Fatalf("status = %q, want invalid", got.Status)
		}
	})
}
