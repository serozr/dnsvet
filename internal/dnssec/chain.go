package dnssec

import (
	"errors"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

const MaxDelegationDepth = 32

// Delegation contains the DNS material needed to authenticate one child zone.
// Records are supplied by the caller; this package does not perform network I/O.
type Delegation struct {
	DSRRset       RRset
	DSSignatures  []*dns.RRSIG
	DNSKEYRRset   RRset
	DNSKEYSignatures []*dns.RRSIG
}

// ChainResult describes the authenticated endpoint of a supplied DNSSEC chain.
type ChainResult struct {
	Zone string
	Keys []*dns.DNSKEY
}

// ValidateChain authenticates a pre-fetched sequence of delegations starting
// from a locally configured trust anchor. Every DS RRset is verified by the
// current authenticated parent keys, then the child DNSKEY RRset is verified
// by a key matched against that authenticated DS RRset.
//
// This function validates supplied material only. It does not discover zones,
// fetch DNS records, validate negative answers, or classify unsigned delegations.
func ValidateChain(
	anchor TrustAnchor,
	anchorRRset RRset,
	anchorSignatures []*dns.RRSIG,
	delegations []Delegation,
	at time.Time,
) (ChainResult, error) {
	if len(delegations) > MaxDelegationDepth {
		return ChainResult{}, fmt.Errorf("delegation depth %d exceeds maximum %d", len(delegations), MaxDelegationDepth)
	}
	keys, err := ValidateTrustAnchorDNSKEYSet(anchorRRset, anchorSignatures, anchor, at)
	if err != nil {
		return ChainResult{}, fmt.Errorf("trust anchor DNSKEY validation failed: %w", err)
	}

	currentZone := dns.Fqdn(anchor.Zone)
	for i, delegation := range delegations {
		if !sameZone(delegation.DSRRset.Name, delegation.DNSKEYRRset.Name) {
			return ChainResult{}, fmt.Errorf("delegation %d DS and DNSKEY owners differ", i)
		}
		matched, err := ValidateDelegationDS(
			currentZone,
			delegation.DSRRset,
			delegation.DSSignatures,
			keys,
			extractDNSKEYs(delegation.DNSKEYRRset),
			at,
		)
		if err != nil {
			return ChainResult{}, fmt.Errorf("delegation %d DS validation failed: %w", i, err)
		}
		childZone := dns.Fqdn(delegation.DNSKEYRRset.Name)
		keys, err = ValidateChildDNSKEYSet(
			childZone,
			delegation.DNSKEYRRset,
			delegation.DNSKEYSignatures,
			matched,
			at,
		)
		if err != nil {
			return ChainResult{}, fmt.Errorf("delegation %d DNSKEY validation failed: %w", i, err)
		}
		currentZone = childZone
	}
	return ChainResult{Zone: currentZone, Keys: keys}, nil
}

func extractDNSKEYs(rrset RRset) []*dns.DNSKEY {
	keys := make([]*dns.DNSKEY, 0, len(rrset.Records))
	for _, record := range rrset.Records {
		key, ok := record.(*dns.DNSKEY)
		if !ok {
			return nil
		}
		keys = append(keys, key)
	}
	return keys
}

func sameZone(a, b string) bool {
	return dns.CanonicalName(a) == dns.CanonicalName(b)
}

var _ = errors.New
