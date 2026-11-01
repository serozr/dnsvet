package dnssec

import (
	"crypto"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func signedChildDNSKEYSet(t *testing.T, at time.Time) (RRset, *dns.RRSIG, *dns.DNSKEY, *dns.DNSKEY) {
	t.Helper()
	ksk, kskSigner := makeSigningKey(t, "child.test.")
	zsk, _ := makeSigningKey(t, "child.test.")
	rrset := RRset{
		Name: "child.test.", Class: dns.ClassINET, Type: dns.TypeDNSKEY,
		Records: []dns.RR{ksk, zsk},
	}
	signature := &dns.RRSIG{
		Hdr: dns.RR_Header{Name: "child.test.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		Algorithm: dns.ED25519,
		Expiration: uint32(at.Add(time.Hour).Unix()),
		Inception: uint32(at.Add(-time.Hour).Unix()),
		KeyTag: ksk.KeyTag(),
		SignerName: "child.test.",
	}
	if err := signature.Sign(kskSigner, rrset.Records); err != nil {
		t.Fatalf("RRSIG.Sign(): %v", err)
	}
	return rrset, signature, ksk, zsk
}

func TestValidateChildDNSKEYSetAcceptsDSAuthenticatedSigner(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, ksk, _ := signedChildDNSKEYSet(t, at)

	keys, err := ValidateChildDNSKEYSet("child.test.", rrset, []*dns.RRSIG{signature}, []*dns.DNSKEY{ksk}, at)
	if err != nil {
		t.Fatalf("ValidateChildDNSKEYSet() error = %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("returned %d keys, want complete two-key RRset", len(keys))
	}
}

func TestValidateChildDNSKEYSetRejectsMissingDSMatchedKey(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, _, _ := signedChildDNSKEYSet(t, at)
	other, _ := makeSigningKey(t, "child.test.")

	_, err := ValidateChildDNSKEYSet("child.test.", rrset, []*dns.RRSIG{signature}, []*dns.DNSKEY{other}, at)
	if !errors.Is(err, ErrNoDSMatchedDNSKEY) {
		t.Fatalf("error = %v, want ErrNoDSMatchedDNSKEY", err)
	}
}

func TestValidateChildDNSKEYSetRejectsTamperedRRset(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, ksk, _ := signedChildDNSKEYSet(t, at)
	rrset.Records[1].(*dns.DNSKEY).PublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

	_, err := ValidateChildDNSKEYSet("child.test.", rrset, []*dns.RRSIG{signature}, []*dns.DNSKEY{ksk}, at)
	if !errors.Is(err, ErrNoValidSignature) {
		t.Fatalf("error = %v, want ErrNoValidSignature", err)
	}
}

func TestValidateChildDNSKEYSetRejectsExpiredSignature(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, ksk, _ := signedChildDNSKEYSet(t, at)
	later := at.Add(2 * time.Hour)

	_, err := ValidateChildDNSKEYSet("child.test.", rrset, []*dns.RRSIG{signature}, []*dns.DNSKEY{ksk}, later)
	if !errors.Is(err, ErrSignatureNotValidAtTime) {
		t.Fatalf("error = %v, want ErrSignatureNotValidAtTime", err)
	}
}

func TestValidateChildDNSKEYSetRejectsWrongZoneAndType(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rrset, signature, ksk, _ := signedChildDNSKEYSet(t, at)

	if _, err := ValidateChildDNSKEYSet("other.test.", rrset, []*dns.RRSIG{signature}, []*dns.DNSKEY{ksk}, at); err == nil {
		t.Fatal("wrong zone accepted")
	}
	rrset.Type = dns.TypeA
	if _, err := ValidateChildDNSKEYSet("child.test.", rrset, []*dns.RRSIG{signature}, []*dns.DNSKEY{ksk}, at); err == nil {
		t.Fatal("non-DNSKEY RRset accepted")
	}
}

var _ crypto.Signer
