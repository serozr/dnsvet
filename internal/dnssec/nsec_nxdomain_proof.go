package dnssec

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ValidateNSECNXDOMAINProof validates an authenticated NSEC denial of existence
// for a non-existent name (NXDOMAIN) according to RFC 4035 Section 5.4 and RFC 7129.
//
// It verifies that:
// 1. All supplied NSEC RRsets are signed by authenticated zone DNSKEYs.
// 2. An NSEC record covers the query name (or proves closest encloser + next closer).
// 3. An NSEC record covers the wildcard at the closest encloser (*.<closest-encloser>).
// 4. No contradictory records exist (e.g. an NSEC matching QNAME or the wildcard).
func ValidateNSECNXDOMAINProof(
	zone string,
	qname string,
	rrsets []RRset,
	signatures [][]*dns.RRSIG,
	zoneKeys []*dns.DNSKEY,
	at time.Time,
) NSECProofResult {
	invalid := func(reason string) NSECProofResult {
		return NSECProofResult{Status: NSECProofInvalid, Reason: reason}
	}
	notProven := func(reason string) NSECProofResult {
		return NSECProofResult{Status: NSECProofNotProven, Reason: reason}
	}

	if !validNSECIntervalName(zone) || !validNSECIntervalName(qname) {
		return invalid("zone or query name is invalid")
	}
	zone = dns.Fqdn(zone)
	query := dns.Fqdn(qname)
	if !isWithinZone(zone, query) {
		return invalid("query name is outside the supplied zone")
	}
	if strings.EqualFold(zone, query) {
		return invalid("zone apex cannot be non-existent (NXDOMAIN)")
	}
	if len(rrsets) == 0 {
		return notProven("no NSEC RRsets supplied for NXDOMAIN proof")
	}
	if len(rrsets) != len(signatures) {
		return invalid("mismatched count between NSEC RRsets and signature sets")
	}
	if len(zoneKeys) == 0 {
		return notProven("authenticated zone DNSKEYs are unavailable")
	}

	for i, key := range zoneKeys {
		if key == nil {
			return invalid(fmt.Sprintf("zone DNSKEY at index %d is nil", i))
		}
		if key.Protocol != 3 {
			continue
		}
		if key.Hdr.Rrtype != dns.TypeDNSKEY ||
			!strings.EqualFold(dns.Fqdn(key.Hdr.Name), zone) {
			return invalid(fmt.Sprintf("zone DNSKEY at index %d does not belong to the supplied zone", i))
		}
	}

	type verifiedNSEC struct {
		nsec  *dns.NSEC
		owner string
		next  string
	}
	verified := make([]verifiedNSEC, 0, len(rrsets))

	for i, rrset := range rrsets {
		if err := validateRRsetMetadata(rrset); err != nil {
			return invalid(fmt.Sprintf("NSEC RRset %d metadata invalid: %v", i, err))
		}
		if rrset.Type != dns.TypeNSEC || rrset.Class != dns.ClassINET || len(rrset.Records) != 1 {
			return invalid(fmt.Sprintf("NSEC RRset %d must contain exactly one IN NSEC record", i))
		}
		owner := dns.Fqdn(rrset.Name)
		if !validNSECIntervalName(owner) || !isWithinZone(zone, owner) {
			return invalid(fmt.Sprintf("NSEC RRset %d owner %q is invalid or outside zone", i, owner))
		}
		nsec, ok := rrset.Records[0].(*dns.NSEC)
		if !ok || nsec == nil {
			return invalid(fmt.Sprintf("RRset %d does not contain a valid NSEC record", i))
		}
		next := dns.Fqdn(nsec.NextDomain)
		if !validNSECIntervalName(next) || !isWithinZone(zone, next) {
			return invalid(fmt.Sprintf("NSEC RRset %d next-domain %q is invalid or outside zone", i, next))
		}

		// Verify signature with authenticated zone keys
		if err := VerifyRRset(rrset, signatures[i], zoneKeys, at); err != nil {
			return invalid(fmt.Sprintf("NSEC RRset %d signature verification failed: %v", i, err))
		}

		if strings.EqualFold(owner, query) {
			return invalid(fmt.Sprintf("NSEC owner %q matches query name; contradicts NXDOMAIN", owner))
		}

		verified = append(verified, verifiedNSEC{nsec: nsec, owner: owner, next: next})
	}

	// 1. Find NSEC covering the query name
	var qnameNSEC *verifiedNSEC
	for i := range verified {
		vn := &verified[i]
		// Delegation cut check: An NSEC at a delegation cut cannot prove non-existence below it
		hasNS, hasSOA := false, false
		for _, typ := range vn.nsec.TypeBitMap {
			switch typ {
			case dns.TypeNS:
				hasNS = true
			case dns.TypeSOA:
				hasSOA = true
			}
		}
		if !strings.EqualFold(vn.owner, zone) && hasNS && !hasSOA && isChildZone(vn.owner, query) {
			continue
		}

		if NSECIntervalCovers(vn.owner, vn.next, query) {
			qnameNSEC = vn
			break
		}
	}

	if qnameNSEC == nil {
		return notProven("no authenticated NSEC interval covers the query name")
	}

	// 2. Determine closest encloser (CE)
	// The closest encloser is the longest ancestor of QNAME that is known to exist.
	// Candidates: ancestors of query up to zone apex.
	ce := zone
	ancestor := query
	for {
		parent := getParentDomain(ancestor)
		if parent == "" || !isWithinZone(zone, parent) {
			break
		}
		// Does parent exist? It exists if it equals zone, or if an NSEC has owner == parent
		for _, vn := range verified {
			if strings.EqualFold(vn.owner, parent) {
				ce = parent
				break
			}
		}
		if strings.EqualFold(ce, parent) {
			break
		}
		ancestor = parent
	}

	// 3. Prove wildcard denial (*.<CE>)
	wildcard := dns.Fqdn("*." + ce)
	// Contradiction check: if an NSEC exists with owner == wildcard, wildcard exists!
	for _, vn := range verified {
		if strings.EqualFold(vn.owner, wildcard) {
			return invalid(fmt.Sprintf("NSEC record for wildcard %q exists; contradicts NXDOMAIN", wildcard))
		}
	}

	var wildcardNSEC *verifiedNSEC
	for i := range verified {
		vn := &verified[i]
		if NSECIntervalCovers(vn.owner, vn.next, wildcard) {
			wildcardNSEC = vn
			break
		}
	}

	if wildcardNSEC == nil {
		return notProven(fmt.Sprintf("no authenticated NSEC covers wildcard %q for closest encloser %q", wildcard, ce))
	}

	return NSECProofResult{
		Status: NSECProofProven,
		Reason: fmt.Sprintf("NXDOMAIN proven by authenticated NSEC records covering %q and wildcard %q", query, wildcard),
	}
}

func getParentDomain(name string) string {
	name = strings.TrimSuffix(dns.Fqdn(name), ".")
	labels := strings.Split(name, ".")
	if len(labels) <= 1 {
		return "."
	}
	return dns.Fqdn(strings.Join(labels[1:], "."))
}
