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
// omit both DS and SOA. Parent DNSKEYs must already be authenticated by caller.
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
	// The final NSEC in a zone points back to the zone apex. This is the
	// canonical-order wrap-around case defined by RFC 4034 section 4.1.1.
	next := dns.Fqdn(nsec.NextDomain)
	if !strings.EqualFold(next, parent) && canonicalNameOrder(child, next) >= 0 {
		return invalid("NSEC next-domain name does not follow its owner in canonical order")
	}

	hasNS := false
	hasDS := false
	hasSOA := false
	for _, typ := range nsec.TypeBitMap {
		switch typ {
		case dns.TypeNS:
			hasNS = true
		case dns.TypeDS:
			hasDS = true
		case dns.TypeSOA:
			hasSOA = true
		}
	}
	if !hasNS {
		return invalid("delegation-point NSEC bitmap does not contain NS")
	}
	if hasSOA {
		return invalid("delegation-point NSEC bitmap contains SOA")
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
		Reason: "parent-authenticated delegation-point NSEC bitmap omits DS and SOA",
	}
}

// canonicalNameOrder implements RFC 4034 section 6.1 ordering. DNS names
// are compared from the rightmost label, using unsigned wire octets and
// ASCII-only case folding. Presentation strings are packed first so escaped
// octets are compared by their DNS value rather than their textual spelling.
func canonicalNameOrder(a, b string) int {
	left, leftErr := canonicalLabels(a)
	right, rightErr := canonicalLabels(b)
	if leftErr != nil || rightErr != nil {
		return 0
	}
	for i, j := len(left)-1, len(right)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if cmp := bytes.Compare(left[i], right[j]); cmp != 0 {
			return cmp
		}
	}
	switch {
	case len(left) < len(right):
		return -1
	case len(left) > len(right):
		return 1
	default:
		return 0
	}
}

func canonicalLabels(name string) ([][]byte, error) {
	wire := make([]byte, 255)
	end, err := dns.PackDomainName(dns.Fqdn(name), wire, 0, nil, false)
	if err != nil {
		return nil, err
	}
	labels := make([][]byte, 0, 8)
	for pos := 0; pos < end; {
		length := int(wire[pos])
		pos++
		if length == 0 {
			break
		}
		label := append([]byte(nil), wire[pos:pos+length]...)
		for i, octet := range label {
			if octet >= 'A' && octet <= 'Z' {
				label[i] = octet + ('a' - 'A')
			}
		}
		labels = append(labels, label)
		pos += length
	}
	return labels, nil
}

func isWithinZone(zone, name string) bool {
	zone = strings.ToLower(dns.Fqdn(zone))
	name = strings.ToLower(dns.Fqdn(name))
	if zone == "." {
		return true
	}
	return name == zone || strings.HasSuffix(name, "."+zone)
}
