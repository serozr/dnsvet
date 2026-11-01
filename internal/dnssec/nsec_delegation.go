package dnssec

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// NSECProofStatus describes whether an NSEC record proves DS absence.
type NSECProofStatus string

const (
	NSECProofProven      NSECProofStatus = "proven"
	NSECProofNotProven   NSECProofStatus = "not_proven"
	NSECProofUnsupported NSECProofStatus = "unsupported"
	NSECProofInvalid     NSECProofStatus = "invalid"
)

// NSECProofResult is the explicit outcome of evaluating one delegation-point
// NSEC record. This is not a general NXDOMAIN or NODATA proof result.
type NSECProofResult struct {
	Status NSECProofStatus
	Reason string
}

// ValidateInsecureDelegationNSEC validates a parent-signed NSEC RRset whose
// owner is exactly the delegation point. The NSEC bitmap must contain NS and
// omit DS. Parent DNSKEYs must already be authenticated by the caller.
//
// This narrow primitive does not implement NSEC interval proofs, wildcard
// proofs, NXDOMAIN/NODATA validation, or NSEC3.
func ValidateInsecureDelegationNSEC(
	parentZone string,
	delegationName string,
	rrset RRset,
	signatures []*dns.RRSIG,
	parentKeys []*dns.DNSKEY,
	at time.Time,
) NSECProofResult {
	invalid := func(reason string) NSECProofResult {
		return NSECProofResult{Status: NSECProofInvalid, Reason: reason}
	}
	notProven := func(reason string) NSECProofResult {
		return NSECProofResult{Status: NSECProofNotProven, Reason: reason}
	}

	if !validDNSName(parentZone) || !validDNSName(delegationName) {
		return invalid("parent or delegation name is invalid")
	}
	parent := dns.Fqdn(parentZone)
	child := dns.Fqdn(delegationName)
	if !isChildZone(parent, child) {
		return invalid("delegation is not below the supplied parent zone")
	}
	if rrset.Type != dns.TypeNSEC || len(rrset.Records) != 1 {
		return invalid("exactly one NSEC record is required")
	}
	if !strings.EqualFold(dns.Fqdn(rrset.Name), child) {
		return invalid("NSEC owner does not exactly match the delegation point")
	}
	if rrset.Class != dns.ClassINET {
		return invalid("unsupported NSEC class")
	}
	if len(parentKeys) == 0 {
		return notProven("authenticated parent DNSKEYs are unavailable")
	}

	nsec, ok := rrset.Records[0].(*dns.NSEC)
	if !ok || nsec == nil {
		return invalid("RRset does not contain an NSEC record")
	}
	if !validDNSName(nsec.NextDomain) {
		return invalid("NSEC next-domain name is invalid")
	}
	if !isWithinZone(parent, nsec.NextDomain) {
		return invalid("NSEC next-domain name is outside the parent zone")
	}
	if canonicalNameOrder(child, nsec.NextDomain) >= 0 {
		return invalid("NSEC next-domain name does not follow its owner in canonical order")
	}

	hasNS := false
	hasDS := false
	for _, typ := range nsec.TypeBitMap {
		switch typ {
		case dns.TypeNS:
			hasNS = true
		case dns.TypeDS:
			hasDS = true
		}
	}
	if !hasNS {
		return invalid("delegation-point NSEC bitmap does not contain NS")
	}
	if hasDS {
		return notProven("NSEC bitmap contains DS")
	}

	for i, key := range parentKeys {
		if key == nil || key.Protocol != 3 ||
			key.Hdr.Class != rrset.Class ||
			!strings.EqualFold(dns.Fqdn(key.Hdr.Name), parent) {
			return invalid(fmt.Sprintf("parent DNSKEY at index %d does not belong to the parent zone", i))
		}
	}
	for i, signature := range signatures {
		if signature == nil {
			continue
		}
		if !strings.EqualFold(dns.Fqdn(signature.SignerName), parent) {
			return invalid(fmt.Sprintf("RRSIG at index %d is not signed by the parent zone", i))
		}
	}

	if err := VerifyRRset(rrset, signatures, parentKeys, at); err != nil {
		return invalid(fmt.Sprintf("NSEC RRset signature validation failed: %v", err))
	}
	return NSECProofResult{
		Status: NSECProofProven,
		Reason: "parent-authenticated delegation-point NSEC bitmap omits DS",
	}
}

// canonicalNameOrder compares DNS names using canonical DNSSEC ordering:
// labels are compared from the root toward the leaf, case-insensitively.
func canonicalNameOrder(a, b string) int {
	aLabels := dns.SplitDomainName(strings.ToLower(dns.Fqdn(a)))
	bLabels := dns.SplitDomainName(strings.ToLower(dns.Fqdn(b)))

	for i, j := len(aLabels)-1, len(bLabels)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if cmp := bytes.Compare([]byte(aLabels[i]), []byte(bLabels[j])); cmp != 0 {
			if cmp < 0 {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(aLabels) < len(bLabels):
		return -1
	case len(aLabels) > len(bLabels):
		return 1
	default:
		return 0
	}
}

func isWithinZone(zone, name string) bool {
	zone = strings.ToLower(dns.Fqdn(zone))
	name = strings.ToLower(dns.Fqdn(name))
	if zone == "." {
		return true
	}
	return name == zone || strings.HasSuffix(name, "."+zone)
}
