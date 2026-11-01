package dnssec

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ValidateNSECIntervalProof verifies one signed NSEC RRset and determines
// whether its canonical interval covers name. zoneKeys must already be
// authenticated for zone by the caller.
//
// This primitive proves only interval coverage. It does not establish a full
// NXDOMAIN/NODATA proof, validate wildcard denial, or process NSEC3 records.
func ValidateNSECIntervalProof(
	zone string,
	name string,
	rrset RRset,
	signatures []*dns.RRSIG,
	zoneKeys []*dns.DNSKEY,
	at time.Time,
) NSECProofResult {
	invalid := func(reason string) NSECProofResult {
		return NSECProofResult{Status: NSECProofInvalid, Reason: reason}
	}
	notProven := func(reason string) NSECProofResult {
		return NSECProofResult{Status: NSECProofNotProven, Reason: reason}
	}

	if !validNSECIntervalName(zone) || !validNSECIntervalName(name) ||
		!validNSECIntervalName(rrset.Name) {
		return invalid("zone, query, or NSEC owner name is invalid")
	}
	zone = dns.Fqdn(zone)
	query := dns.Fqdn(name)
	owner := dns.Fqdn(rrset.Name)
	if !isWithinZone(zone, query) {
		return invalid("query name is outside the supplied zone")
	}
	if !isWithinZone(zone, owner) {
		return invalid("NSEC owner is outside the supplied zone")
	}
	if rrset.Type != dns.TypeNSEC || rrset.Class != dns.ClassINET || len(rrset.Records) != 1 {
		return invalid("exactly one IN-class NSEC record is required")
	}
	nsec, ok := rrset.Records[0].(*dns.NSEC)
	if !ok || nsec == nil {
		return invalid("RRset does not contain an NSEC record")
	}
	if !validNSECIntervalName(nsec.NextDomain) {
		return invalid("NSEC next-domain name is invalid")
	}
	next := dns.Fqdn(nsec.NextDomain)
	if !isWithinZone(zone, next) {
		return invalid("NSEC next-domain name is outside the supplied zone")
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
		if key.Hdr.Rrtype != dns.TypeDNSKEY || key.Hdr.Class != rrset.Class ||
			!strings.EqualFold(dns.Fqdn(key.Hdr.Name), zone) {
			return invalid(fmt.Sprintf("zone DNSKEY at index %d does not belong to the supplied zone", i))
		}
	}
	for i, signature := range signatures {
		if signature == nil {
			continue
		}
		if !strings.EqualFold(dns.Fqdn(signature.SignerName), zone) {
			return invalid(fmt.Sprintf("RRSIG at index %d is not signed by the supplied zone", i))
		}
	}

	if err := VerifyRRset(rrset, signatures, zoneKeys, at); err != nil {
		return invalid(fmt.Sprintf("NSEC RRset signature validation failed: %v", err))
	}
	// An NSEC at a delegation point cannot, by itself, prove non-existence
	// below that cut. The child zone may contain names absent from the
	// parent's authoritative view.
	hasNS, hasSOA := false, false
	for _, typ := range nsec.TypeBitMap {
		if typ == dns.TypeNS {
			hasNS = true
		}
		if typ == dns.TypeSOA {
			hasSOA = true
		}
	}
	if !strings.EqualFold(owner, zone) && hasNS && !hasSOA && isChildZone(owner, query) {
		return notProven("query is below an NSEC delegation point; parent-zone interval is insufficient")
	}
	if !NSECIntervalCovers(owner, next, query) {
		return notProven("authenticated NSEC interval does not cover the query name")
	}
	return NSECProofResult{
		Status: NSECProofProven,
		Reason: "zone-authenticated NSEC interval covers the query name",
	}
}
