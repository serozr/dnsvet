package dnssec

import (
	"context"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type mockResolver struct {
	responses map[string]*dns.Msg
}

func (m *mockResolver) Query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := fmtQueryKey(name, qtype)
	if resp, ok := m.responses[key]; ok {
		return resp, nil
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.Rcode = dns.RcodeNameError
	return msg, nil
}

func fmtQueryKey(name string, qtype uint16) string {
	return dns.Fqdn(name) + ":" + dns.TypeToString[qtype]
}

func TestValidatorPositiveAnswerSuccess(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	const zone = "example.test."
	key, signer := makeSigningKey(t, zone)

	v := NewValidator(nil, nil)
	v.SetTime(at)

	qname := "www.example.test."
	aRecord := &dns.A{
		Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   net.ParseIP("192.0.2.1"),
	}
	rrset := RRset{Name: qname, Class: dns.ClassINET, Type: dns.TypeA, Records: []dns.RR{aRecord}}
	sig := signTestRRset(t, rrset, key, signer, at)

	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeA)
	msg.Answer = []dns.RR{aRecord, sig}

	res := v.ValidateResponseWithKeys(qname, dns.TypeA, msg, zone, []*dns.DNSKEY{key})
	if res.Status != StatusSecure {
		t.Fatalf("expected StatusSecure, got %s, reason=%s", res.Status, res.Reason)
	}
	if len(res.SecureRRsets) != 1 || res.ProofType != "positive" {
		t.Fatalf("unexpected res: %+v", res)
	}
}

func TestValidatorPositiveAnswerRejectsTamperedRecord(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	const zone = "example.test."
	key, signer := makeSigningKey(t, zone)

	v := NewValidator(nil, nil)
	v.SetTime(at)

	qname := "www.example.test."
	aRecord := &dns.A{
		Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   net.ParseIP("192.0.2.1"),
	}
	rrset := RRset{Name: qname, Class: dns.ClassINET, Type: dns.TypeA, Records: []dns.RR{aRecord}}
	sig := signTestRRset(t, rrset, key, signer, at)

	// Tamper record IP
	aRecord.A = net.ParseIP("192.0.2.99")

	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeA)
	msg.Answer = []dns.RR{aRecord, sig}

	res := v.ValidateResponseWithKeys(qname, dns.TypeA, msg, zone, []*dns.DNSKEY{key})
	if res.Status != StatusBogus {
		t.Fatalf("expected StatusBogus for tampered record, got %s", res.Status)
	}
}

func TestValidatorPositiveAnswerRejectsMissingSignature(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	const zone = "example.test."
	key, _ := makeSigningKey(t, zone)

	v := NewValidator(nil, nil)
	v.SetTime(at)

	qname := "www.example.test."
	aRecord := &dns.A{
		Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   net.ParseIP("192.0.2.1"),
	}

	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeA)
	msg.Answer = []dns.RR{aRecord}

	res := v.ValidateResponseWithKeys(qname, dns.TypeA, msg, zone, []*dns.DNSKEY{key})
	if res.Status != StatusBogus {
		t.Fatalf("expected StatusBogus for missing signature, got %s", res.Status)
	}
}

func TestValidatorNXDOMAINWithNSEC(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	const zone = "example.test."
	key, signer := makeSigningKey(t, zone)

	v := NewValidator(nil, nil)
	v.SetTime(at)

	nsec := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: zone, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600},
		NextDomain: zone,
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY},
	}
	rrset := RRset{Name: zone, Class: dns.ClassINET, Type: dns.TypeNSEC, Records: []dns.RR{nsec}}
	sig := signTestRRset(t, rrset, key, signer, at)

	msg := new(dns.Msg)
	msg.SetQuestion("missing.example.test.", dns.TypeA)
	msg.Rcode = dns.RcodeNameError
	msg.Ns = []dns.RR{nsec, sig}

	res := v.ValidateResponseWithKeys("missing.example.test.", dns.TypeA, msg, zone, []*dns.DNSKEY{key})
	if res.Status != StatusSecure || res.ProofType != "nsec_nxdomain" {
		t.Fatalf("expected StatusSecure with nsec_nxdomain, got status=%s, proof=%s, reason=%s", res.Status, res.ProofType, res.Reason)
	}
}

func TestValidatorNXDOMAINMissingProofsIsBogus(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	const zone = "example.test."
	key, _ := makeSigningKey(t, zone)

	v := NewValidator(nil, nil)
	v.SetTime(at)

	msg := new(dns.Msg)
	msg.SetQuestion("missing.example.test.", dns.TypeA)
	msg.Rcode = dns.RcodeNameError

	res := v.ValidateResponseWithKeys("missing.example.test.", dns.TypeA, msg, zone, []*dns.DNSKEY{key})
	if res.Status != StatusBogus {
		t.Fatalf("expected StatusBogus for NXDOMAIN with no denial proofs, got %s", res.Status)
	}
}

func TestValidatorDynamicChainValidationSuccess(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

	// Anchor zone test.
	testKey, testSigner := makeSigningKey(t, "test.")
	anchor := TrustAnchor{Zone: "test.", DNSKEY: testKey}

	// test. DNSKEY message
	testDNSKEYMsg := new(dns.Msg)
	testDNSKEYMsg.SetQuestion("test.", dns.TypeDNSKEY)
	testKeySet := RRset{Name: "test.", Class: dns.ClassINET, Type: dns.TypeDNSKEY, Records: []dns.RR{testKey}}
	testKeySig := signTestRRset(t, testKeySet, testKey, testSigner, at)
	testDNSKEYMsg.Answer = []dns.RR{testKey, testKeySig}

	// Child zone example.test. (direct delegation cut from test.)
	childZone := "example.test."
	childKey, childSigner := makeSigningKey(t, childZone)

	// DS message for example.test. queried from test.
	dsMsg := new(dns.Msg)
	dsMsg.SetQuestion(childZone, dns.TypeDS)
	dsRR := childKey.ToDS(dns.SHA256)
	dsSet := RRset{Name: childZone, Class: dns.ClassINET, Type: dns.TypeDS, Records: []dns.RR{dsRR}}
	dsSig := signTestRRset(t, dsSet, testKey, testSigner, at)
	dsMsg.Answer = []dns.RR{dsRR, dsSig}

	// Child DNSKEY message
	childDNSKEYMsg := new(dns.Msg)
	childDNSKEYMsg.SetQuestion(childZone, dns.TypeDNSKEY)
	childKeySet := RRset{Name: childZone, Class: dns.ClassINET, Type: dns.TypeDNSKEY, Records: []dns.RR{childKey}}
	childKeySig := signTestRRset(t, childKeySet, childKey, childSigner, at)
	childDNSKEYMsg.Answer = []dns.RR{childKey, childKeySig}

	resolver := &mockResolver{
		responses: map[string]*dns.Msg{
			"test.:DNSKEY":         testDNSKEYMsg,
			"example.test.:DS":     dsMsg,
			"example.test.:DNSKEY": childDNSKEYMsg,
		},
	}

	v := NewValidator([]TrustAnchor{anchor}, resolver)
	v.SetTime(at)

	// Target query: www.example.test. A
	qname := "www.example.test."
	aRecord := &dns.A{
		Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   net.ParseIP("192.0.2.1"),
	}
	targetSet := RRset{Name: qname, Class: dns.ClassINET, Type: dns.TypeA, Records: []dns.RR{aRecord}}
	targetSig := signTestRRset(t, targetSet, childKey, childSigner, at)

	response := new(dns.Msg)
	response.SetQuestion(qname, dns.TypeA)
	response.Answer = []dns.RR{aRecord, targetSig}

	res := v.Validate(context.Background(), qname, dns.TypeA, response)
	if res.Status != StatusSecure {
		t.Fatalf("expected StatusSecure, got %s, reason=%s", res.Status, res.Reason)
	}
	if res.Zone != "example.test." {
		t.Fatalf("expected Zone example.test., got %s", res.Zone)
	}
	if res.TrustAnchor != "test." {
		t.Fatalf("expected TrustAnchor test., got %s", res.TrustAnchor)
	}
}

func TestValidatorDynamicInsecureDelegationNSEC(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

	testKey, testSigner := makeSigningKey(t, "test.")
	anchor := TrustAnchor{Zone: "test.", DNSKEY: testKey}

	testDNSKEYMsg := new(dns.Msg)
	testDNSKEYMsg.SetQuestion("test.", dns.TypeDNSKEY)
	testKeySet := RRset{Name: "test.", Class: dns.ClassINET, Type: dns.TypeDNSKEY, Records: []dns.RR{testKey}}
	testKeySig := signTestRRset(t, testKeySet, testKey, testSigner, at)
	testDNSKEYMsg.Answer = []dns.RR{testKey, testKeySig}

	// Delegation at unsigned.test. has NO DS; returns NSEC in authority section
	unsignedZone := "unsigned.test."
	dsMsg := new(dns.Msg)
	dsMsg.SetQuestion(unsignedZone, dns.TypeDS)
	dsMsg.Rcode = dns.RcodeSuccess

	nsec := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: unsignedZone, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 3600},
		NextDomain: "test.",
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC}, // NS without DS or SOA
	}
	nsecSet := RRset{Name: unsignedZone, Class: dns.ClassINET, Type: dns.TypeNSEC, Records: []dns.RR{nsec}}
	nsecSig := signTestRRset(t, nsecSet, testKey, testSigner, at)
	dsMsg.Ns = []dns.RR{nsec, nsecSig}

	resolver := &mockResolver{
		responses: map[string]*dns.Msg{
			"test.:DNSKEY":      testDNSKEYMsg,
			"unsigned.test.:DS": dsMsg,
		},
	}

	v := NewValidator([]TrustAnchor{anchor}, resolver)
	v.SetTime(at)

	// An unsigned answer from unsigned.test.
	response := new(dns.Msg)
	response.SetQuestion("www.unsigned.test.", dns.TypeA)
	response.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "www.unsigned.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   net.ParseIP("192.0.2.1"),
	}}

	res := v.Validate(context.Background(), "www.unsigned.test.", dns.TypeA, response)
	if res.Status != StatusInsecure {
		t.Fatalf("expected StatusInsecure for authenticated unsigned delegation, got %s, reason=%s", res.Status, res.Reason)
	}
}

func TestValidatorDynamicInsecureDelegationNSEC3OptOut(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

	testKey, testSigner := makeSigningKey(t, "test.")
	anchor := TrustAnchor{Zone: "test.", DNSKEY: testKey}

	testDNSKEYMsg := new(dns.Msg)
	testDNSKEYMsg.SetQuestion("test.", dns.TypeDNSKEY)
	testKeySet := RRset{Name: "test.", Class: dns.ClassINET, Type: dns.TypeDNSKEY, Records: []dns.RR{testKey}}
	testKeySig := signTestRRset(t, testKeySet, testKey, testSigner, at)
	testDNSKEYMsg.Answer = []dns.RR{testKey, testKeySig}

	unsignedZone := "unsigned.test."
	dsMsg := new(dns.Msg)
	dsMsg.SetQuestion(unsignedZone, dns.TypeDS)
	dsMsg.Rcode = dns.RcodeSuccess

	salt := []byte{0x01, 0x02}
	saltHex := hex.EncodeToString(salt)
	nsec3 := &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: "00000000000000000000000000000000.test.", Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 3600},
		Hash:       1,
		Flags:      NSEC3OptOut,
		Iterations: 5,
		SaltLength: uint8(len(salt)),
		Salt:       saltHex,
		HashLength: 20,
		NextDomain: "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv",
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG},
	}
	nsec3Set := RRset{Name: "00000000000000000000000000000000.test.", Class: dns.ClassINET, Type: dns.TypeNSEC3, Records: []dns.RR{nsec3}}
	nsec3Sig := signTestRRset(t, nsec3Set, testKey, testSigner, at)
	dsMsg.Ns = []dns.RR{nsec3, nsec3Sig}

	resolver := &mockResolver{
		responses: map[string]*dns.Msg{
			"test.:DNSKEY":      testDNSKEYMsg,
			"unsigned.test.:DS": dsMsg,
		},
	}

	v := NewValidator([]TrustAnchor{anchor}, resolver)
	v.SetTime(at)

	response := new(dns.Msg)
	response.SetQuestion("www.unsigned.test.", dns.TypeA)
	response.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "www.unsigned.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   net.ParseIP("192.0.2.1"),
	}}

	res := v.Validate(context.Background(), "www.unsigned.test.", dns.TypeA, response)
	if res.Status != StatusInsecure {
		t.Fatalf("expected StatusInsecure for NSEC3 Opt-Out delegation, got %s, reason=%s", res.Status, res.Reason)
	}
}

func TestValidatorDynamicContextCancellation(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	testKey, _ := makeSigningKey(t, "test.")
	anchor := TrustAnchor{Zone: "test.", DNSKEY: testKey}

	v := NewValidator([]TrustAnchor{anchor}, &mockResolver{responses: nil})
	v.SetTime(at)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	res := v.Validate(ctx, "www.example.test.", dns.TypeA, new(dns.Msg))
	if res.Status != StatusIndeterminate {
		t.Fatalf("expected StatusIndeterminate on cancelled context, got %s", res.Status)
	}
}

func TestValidatorDynamicMismatchedDSDigestIsBogus(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	testKey, testSigner := makeSigningKey(t, "test.")
	anchor := TrustAnchor{Zone: "test.", DNSKEY: testKey}

	testDNSKEYMsg := new(dns.Msg)
	testDNSKEYMsg.SetQuestion("test.", dns.TypeDNSKEY)
	testKeySet := RRset{Name: "test.", Class: dns.ClassINET, Type: dns.TypeDNSKEY, Records: []dns.RR{testKey}}
	testKeySig := signTestRRset(t, testKeySet, testKey, testSigner, at)
	testDNSKEYMsg.Answer = []dns.RR{testKey, testKeySig}

	childZone := "example.test."
	childKey, childSigner := makeSigningKey(t, childZone)

	// Tampered DS digest
	dsRR := childKey.ToDS(dns.SHA256)
	dsRR.Digest = "0000000000000000000000000000000000000000000000000000000000000000"
	dsSet := RRset{Name: childZone, Class: dns.ClassINET, Type: dns.TypeDS, Records: []dns.RR{dsRR}}
	dsSig := signTestRRset(t, dsSet, testKey, testSigner, at)

	dsMsg := new(dns.Msg)
	dsMsg.SetQuestion(childZone, dns.TypeDS)
	dsMsg.Answer = []dns.RR{dsRR, dsSig}

	childDNSKEYMsg := new(dns.Msg)
	childDNSKEYMsg.SetQuestion(childZone, dns.TypeDNSKEY)
	childKeySet := RRset{Name: childZone, Class: dns.ClassINET, Type: dns.TypeDNSKEY, Records: []dns.RR{childKey}}
	childKeySig := signTestRRset(t, childKeySet, childKey, childSigner, at)
	childDNSKEYMsg.Answer = []dns.RR{childKey, childKeySig}

	resolver := &mockResolver{
		responses: map[string]*dns.Msg{
			"test.:DNSKEY":         testDNSKEYMsg,
			"example.test.:DS":     dsMsg,
			"example.test.:DNSKEY": childDNSKEYMsg,
		},
	}

	v := NewValidator([]TrustAnchor{anchor}, resolver)
	v.SetTime(at)

	res := v.Validate(context.Background(), "www.example.test.", dns.TypeA, new(dns.Msg))
	if res.Status != StatusBogus {
		t.Fatalf("expected StatusBogus on mismatched DS digest, got %s, reason=%s", res.Status, res.Reason)
	}
}
