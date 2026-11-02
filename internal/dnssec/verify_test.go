package dnssec

import (
	"crypto"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func signedTestRRset(t *testing.T, at time.Time) (RRset, *dns.RRSIG, *dns.DNSKEY) {
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

	records := []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "www.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{192, 0, 2, 10},
		},
	}
	rrset := RRset{Name: "www.example.test.", Class: dns.ClassINET, Type: dns.TypeA, Records: records}
	signature := &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: "www.example.test.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
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

func TestVerifyRRsetAcceptsValidEd25519Signature(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, key := signedTestRRset(t, at)

	if err := VerifyRRset(rrset, []*dns.RRSIG{signature}, []*dns.DNSKEY{key}, at); err != nil {
		t.Fatalf("VerifyRRset() error = %v", err)
	}
}

func TestVerifyRRsetRejectsTamperedRecord(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, key := signedTestRRset(t, at)
	rrset.Records[0].(*dns.A).A = []byte{192, 0, 2, 11}

	err := VerifyRRset(rrset, []*dns.RRSIG{signature}, []*dns.DNSKEY{key}, at)
	if !errors.Is(err, ErrNoValidSignature) {
		t.Fatalf("error = %v, want ErrNoValidSignature", err)
	}
}

func TestVerifyRRsetRejectsExpiredSignature(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, key := signedTestRRset(t, at)
	future := at.Add(2 * time.Hour)

	err := VerifyRRset(rrset, []*dns.RRSIG{signature}, []*dns.DNSKEY{key}, future)
	if !errors.Is(err, ErrSignatureNotValidAtTime) {
		t.Fatalf("error = %v, want ErrSignatureNotValidAtTime", err)
	}
}

func TestVerifyRRsetRejectsMissingSignatureAndKey(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, key := signedTestRRset(t, at)

	if err := VerifyRRset(rrset, nil, []*dns.DNSKEY{key}, at); !errors.Is(err, ErrNoSignatures) {
		t.Fatalf("missing signature error = %v", err)
	}
	if err := VerifyRRset(rrset, []*dns.RRSIG{signature}, nil, at); !errors.Is(err, ErrNoMatchingKey) {
		t.Fatalf("missing key error = %v", err)
	}
}

func TestVerifyRRsetRejectsMismatchedRRsetRecord(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, key := signedTestRRset(t, at)
	rrset.Records = append(rrset.Records, &dns.A{
		Hdr: dns.RR_Header{Name: "other.example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   []byte{192, 0, 2, 12},
	})

	if err := VerifyRRset(rrset, []*dns.RRSIG{signature}, []*dns.DNSKEY{key}, at); err == nil {
		t.Fatal("VerifyRRset() error = nil, want RRset structure error")
	}
}

func TestVerifyRRsetRejectsInvalidMetadata(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, key := signedTestRRset(t, at)
	for name, mutate := range map[string]func(*RRset){
		"empty owner": func(rrset *RRset) { rrset.Name = "" },
		"zero class":  func(rrset *RRset) { rrset.Class = 0 },
		"zero type":   func(rrset *RRset) { rrset.Type = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			malformed := rrset
			mutate(&malformed)
			if err := VerifyRRset(malformed, []*dns.RRSIG{signature}, []*dns.DNSKEY{key}, at); err == nil {
				t.Fatal("VerifyRRset() error = nil, want metadata error")
			}
		})
	}
}

func TestVerifyRRsetRequiresExplicitTime(t *testing.T) {
	rrset, signature, key := signedTestRRset(t, time.Now().UTC())
	if err := VerifyRRset(rrset, []*dns.RRSIG{signature}, []*dns.DNSKEY{key}, time.Time{}); err == nil {
		t.Fatal("VerifyRRset() error = nil, want explicit-time error")
	}
}

func TestVerifyRRsetIgnoresNonProtocolThreeSigningKey(t *testing.T) {
	rrset, signature, key := signedTestRRset(t, time.Now().UTC())
	invalidKey := *key
	invalidKey.Protocol = 2

	if err := VerifyRRset(rrset, []*dns.RRSIG{signature}, []*dns.DNSKEY{&invalidKey}, time.Now().UTC()); !errors.Is(err, ErrNoMatchingKey) {
		t.Fatalf("VerifyRRset() error = %v, want ErrNoMatchingKey", err)
	}
}

func TestVerifyRRsetRejectsExcessiveValidationInput(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, key := signedTestRRset(t, at)

	t.Run("records", func(t *testing.T) {
		oversized := rrset
		oversized.Records = make([]dns.RR, MaxRRsetRecords+1)
		if err := VerifyRRset(oversized, []*dns.RRSIG{signature}, []*dns.DNSKEY{key}, at); err == nil {
			t.Fatal("VerifyRRset() error = nil, want record limit error")
		}
	})
	t.Run("signatures", func(t *testing.T) {
		signatures := make([]*dns.RRSIG, MaxRRsetSignatures+1)
		if err := VerifyRRset(rrset, signatures, []*dns.DNSKEY{key}, at); err == nil {
			t.Fatal("VerifyRRset() error = nil, want signature limit error")
		}
	})
	t.Run("keys", func(t *testing.T) {
		keys := make([]*dns.DNSKEY, MaxValidationKeys+1)
		if err := VerifyRRset(rrset, []*dns.RRSIG{signature}, keys, at); err == nil {
			t.Fatal("VerifyRRset() error = nil, want key limit error")
		}
	})
}

func TestVerifyRRsetRejectsDuplicateRecords(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, key := signedTestRRset(t, at)
	rrset.Records = append(rrset.Records, dns.Copy(rrset.Records[0]))

	if err := VerifyRRset(rrset, []*dns.RRSIG{signature}, []*dns.DNSKEY{key}, at); err == nil {
		t.Fatal("VerifyRRset() error = nil, want duplicate-record error")
	}
}
