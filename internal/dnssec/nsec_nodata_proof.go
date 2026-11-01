package dnssec

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ValidateNSECNoDataProof validates a narrow exact-owner NSEC proof for an
// authoritative NODATA response. zoneKeys must already be authenticated for
// zone by the caller.
//
// It requires the NSEC owner to equal QNAME and verifies that the signed
// bitmap omits both QTYPE and CNAME (RFC 6840, Section 4.3). It rejects
// delegation-point records and unsupported query types. This primitive does
// not validate a complete DNS response, wildcard processing, ancestor
// delegation handling, or NSEC3.
func ValidateNSECNoDataProof(
	zone string,
	name string,
	qtype uint16,
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
	unsupported := func(reason string) NSECProofResult {
		return NSECProofResult{Status: NSECProofUnsupported, Reason: reason}
	}

	if !validNSECIntervalName(zone) || !validNSECIntervalName(name) ||
		!validNSECIntervalName(rrset.Name) {
		return invalid("zone, query, or NSEC owner name is invalid")
	}
	if qtype == 0 {
		return invalid("query type must be non-zero")
	}
	switch qtype {
	case dns.TypeANY, dns.TypeNSEC, dns.TypeRRSIG:
		return unsupported("query type is outside the supported NODATA proof scope")
	}

	zone = dns.Fqdn(zone)
	query := dns.Fqdn(name)
	owner := dns.Fqdn(rrset.Name)
	if !isWithinZone(zone, query) {
		return invalid("query name is outside the supplied zone")
	}
	if !strings.EqualFold(query, owner) {
		return notProven("NSEC owner does not exactly match the query name")
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
	if !isWithinZone(zone, nsec.NextDomain) {
		return invalid("NSEC next-domain name is outside the supplied zone")
	}

	// A non-apex NS-without-SOA owner is a delegation point, not an ordinary
	// authoritative owner for this proof. DS absence is handled separately.
	hasNS, hasSOA := false, false
	for _, typ := range nsec.TypeBitMap {
		switch typ {
		case dns.TypeNS:
			hasNS = true
		case dns.TypeSOA:
			hasSOA = true
		}
	}
	if hasNS && !hasSOA && !strings.EqualFold(owner, zone) {
		return notProven("delegation-point NSEC requires dedicated DS/referral validation")
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

	hasQType, hasCNAME := false, false
	for _, typ := range nsec.TypeBitMap {
		if typ == qtype {
			hasQType = true
		}
		if typ == dns.TypeCNAME {
			hasCNAME = true
		}
	}
	if hasQType {
		return notProven("NSEC bitmap contains the queried RR type")
	}
	if hasCNAME {
		return notProven("NSEC bitmap contains CNAME; NODATA is not proven")
	}

	return NSECProofResult{
		Status: NSECProofProven,
		Reason: "authenticated exact-owner NSEC bitmap omits both the queried type and CNAME",
	}
}
