package dnssec

import (
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
		DSRRset: RRset{Name: "child.example.test.", Type: dns.TypeDS},
		DNSKEYRRset: RRset{Name: "other.example.test.", Type: dns.TypeDNSKEY},
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
