package dnssec

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestNSEC3RFC5155TestVectors tests against the published RFC 5155 Appendix A vectors.
func TestNSEC3RFC5155TestVectors(t *testing.T) {
	salt, err := hex.DecodeString("aabbccdd")
	if err != nil {
		t.Fatalf("hex.DecodeString(): %v", err)
	}
	const (
		alg  = 1
		iter = 12
	)

	vectors := []struct {
		name string
		want string
	}{
		{"example.", "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"},
		{"a.example.", "35mthgpgcu1qg68fab165klnsnk3dpvl"},
		{"ai.example.", "gjeqe526plbf1g8mklp59enfd789njgi"},
		{"ns1.example.", "2t7b4g4vsa5smi47k61mv5bv1a22bojr"},
		{"ns2.example.", "q04jkcevqvmu85r014c7dkba38o0ji5r"},
		{"w.example.", "k8udemvp1j2f7eg6jebps17vp3n8i58h"},
		{"*.w.example.", "r53bq7cc2uvmubfu5ocmm6pers9tk9en"},
		{"x.w.example.", "b4um86eghhds6nea196smvmlo4ors995"},
		{"xx.example.", "t644ebqk9bibcna874givr6joj62mlhv"},
	}

	for _, tt := range vectors {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HashNSEC3Name(tt.name, alg, iter, salt)
			if err != nil {
				t.Fatalf("HashNSEC3Name(%q) error = %v", tt.name, err)
			}
			if got != tt.want {
				t.Fatalf("HashNSEC3Name(%q) = %q, want RFC 5155 vector %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestNSEC3RejectsExcessiveIterations(t *testing.T) {
	_, err := HashNSEC3Name("example.com.", 1, 150, []byte("salt"))
	if err == nil {
		t.Fatal("expected error for iterations > 100, got nil")
	}
}

func TestNSEC3RejectsUnsupportedAlgorithm(t *testing.T) {
	_, err := HashNSEC3Name("example.com.", 2, 10, []byte("salt"))
	if err == nil {
		t.Fatal("expected error for algorithm 2, got nil")
	}
}

func TestNSEC3IntervalCovers(t *testing.T) {
	tests := []struct {
		name   string
		owner  string
		next   string
		target string
		want   bool
	}{
		{"standard interval inside", "20", "40", "30", true},
		{"standard interval below", "20", "40", "10", false},
		{"standard interval above", "20", "40", "50", false},
		{"standard interval lower bound", "20", "40", "20", false},
		{"standard interval upper bound", "20", "40", "40", false},
		{"wrap-around inside above owner", "80", "20", "90", true},
		{"wrap-around inside below next", "80", "20", "10", true},
		{"wrap-around outside between next and owner", "80", "20", "50", false},
		{"single record zone different target", "20", "20", "30", true},
		{"single record zone same target", "20", "20", "20", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NSEC3IntervalCovers(tt.owner, tt.next, tt.target)
			if got != tt.want {
				t.Fatalf("NSEC3IntervalCovers(%q, %q, %q) = %t, want %t", tt.owner, tt.next, tt.target, got, tt.want)
			}
		})
	}
}

func TestValidateNSEC3NoDataProofExactMatch(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	const zone = "example.test."
	key, signer := makeSigningKey(t, zone)

	salt := []byte{0xaa, 0xbb}
	saltHex := hex.EncodeToString(salt)
	qname := "www.example.test."
	hash, err := HashNSEC3Name(qname, 1, 10, salt)
	if err != nil {
		t.Fatalf("HashNSEC3Name(): %v", err)
	}

	ownerName := hash + "." + zone
	nsec3 := &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: ownerName, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 3600},
		Hash:       1,
		Flags:      0,
		Iterations: 10,
		SaltLength: uint8(len(salt)),
		Salt:       saltHex,
		HashLength: 20,
		NextDomain: "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv",
		TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG}, // Has A, but no AAAA or TXT
	}
	rrset := RRset{Name: ownerName, Class: dns.ClassINET, Type: dns.TypeNSEC3, Records: []dns.RR{nsec3}}
	sig := signTestRRset(t, rrset, key, signer, at)

	// Query for TXT -> should be PROVEN (NODATA)
	res := ValidateNSEC3NoDataProof(
		zone,
		qname,
		dns.TypeTXT,
		[]RRset{rrset},
		[][]*dns.RRSIG{{sig}},
		[]*dns.DNSKEY{key},
		at,
	)
	if res.Status != NSECProofProven {
		t.Fatalf("expected NSECProofProven, got status=%s, reason=%s", res.Status, res.Reason)
	}

	// Query for A -> should be INVALID (A exists in bitmap)
	resA := ValidateNSEC3NoDataProof(
		zone,
		qname,
		dns.TypeA,
		[]RRset{rrset},
		[][]*dns.RRSIG{{sig}},
		[]*dns.DNSKEY{key},
		at,
	)
	if resA.Status != NSECProofInvalid {
		t.Fatalf("expected NSECProofInvalid for existing type A, got %s", resA.Status)
	}
}

func TestValidateNSEC3InsecureDelegationOptOut(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	const parentZone = "example.test."
	key, signer := makeSigningKey(t, parentZone)

	salt := []byte{0x01, 0x02}
	saltHex := hex.EncodeToString(salt)
	delegation := "unsigned.example.test."
	delHash, _ := HashNSEC3Name(delegation, 1, 5, salt)

	// An NSEC3 record covering delHash with Opt-Out flag set
	ownerHash := "00000000000000000000000000000000"
	nextHash := "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"
	ownerName := ownerHash + "." + parentZone

	nsec3 := &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: ownerName, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 3600},
		Hash:       1,
		Flags:      NSEC3OptOut,
		Iterations: 5,
		SaltLength: uint8(len(salt)),
		Salt:       saltHex,
		HashLength: 20,
		NextDomain: nextHash,
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG},
	}
	rrset := RRset{Name: ownerName, Class: dns.ClassINET, Type: dns.TypeNSEC3, Records: []dns.RR{nsec3}}
	sig := signTestRRset(t, rrset, key, signer, at)

	res := ValidateNSEC3InsecureDelegation(
		parentZone,
		delegation,
		[]RRset{rrset},
		[][]*dns.RRSIG{{sig}},
		[]*dns.DNSKEY{key},
		at,
	)
	if res.Status != NSECProofProven {
		t.Fatalf("expected NSECProofProven for Opt-Out delegation, got status=%s, reason=%s", res.Status, res.Reason)
	}
	_ = delHash
}

func TestValidateNSEC3NXDOMAINProof(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	const zone = "example.test."
	key, signer := makeSigningKey(t, zone)

	salt := []byte{0xaa, 0xbb}
	saltHex := hex.EncodeToString(salt)
	qname := "missing.example.test."

	// 1. Closest encloser is zone apex (example.test.)
	ceHash, err := HashNSEC3Name(zone, 1, 10, salt)
	if err != nil {
		t.Fatalf("HashNSEC3Name(ce): %v", err)
	}

	// 2. Next closer is missing.example.test.
	ncHash, err := HashNSEC3Name(qname, 1, 10, salt)
	if err != nil {
		t.Fatalf("HashNSEC3Name(nc): %v", err)
	}

	// 3. Wildcard is *.example.test.
	wildcard := "*.example.test."
	wHash, err := HashNSEC3Name(wildcard, 1, 10, salt)
	if err != nil {
		t.Fatalf("HashNSEC3Name(wildcard): %v", err)
	}

	_ = ncHash
	_ = wHash

	// CE NSEC3 matching ceHash
	ceOwner := ceHash + "." + zone
	ceNSEC3 := &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: ceOwner, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 3600},
		Hash:       1,
		Flags:      0,
		Iterations: 10,
		SaltLength: uint8(len(salt)),
		Salt:       saltHex,
		HashLength: 20,
		NextDomain: "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv",
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG},
	}
	ceRRset := RRset{Name: ceOwner, Class: dns.ClassINET, Type: dns.TypeNSEC3, Records: []dns.RR{ceNSEC3}}
	ceSig := signTestRRset(t, ceRRset, key, signer, at)

	// Covering NSEC3 that wraps the whole space from 00.. to 00..
	// It covers ncHash and wHash
	covOwner := "00000000000000000000000000000000." + zone
	covNSEC3 := &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: covOwner, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 3600},
		Hash:       1,
		Flags:      0,
		Iterations: 10,
		SaltLength: uint8(len(salt)),
		Salt:       saltHex,
		HashLength: 20,
		NextDomain: "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv",
		TypeBitMap: []uint16{dns.TypeRRSIG},
	}
	covRRset := RRset{Name: covOwner, Class: dns.ClassINET, Type: dns.TypeNSEC3, Records: []dns.RR{covNSEC3}}
	covSig := signTestRRset(t, covRRset, key, signer, at)

	res := ValidateNSEC3NXDOMAINProof(
		zone,
		qname,
		[]RRset{ceRRset, covRRset},
		[][]*dns.RRSIG{{ceSig}, {covSig}},
		[]*dns.DNSKEY{key},
		at,
	)
	if res.Status != NSECProofProven {
		t.Fatalf("expected NSECProofProven for NSEC3 NXDOMAIN, got status=%s, reason=%s", res.Status, res.Reason)
	}
}
