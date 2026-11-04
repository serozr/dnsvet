package dnssec

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Resolver defines the transport abstraction needed by Validator
// to retrieve intermediate DS and DNSKEY records during chain walking.
type Resolver interface {
	Query(ctx context.Context, name string, qtype uint16) (*dns.Msg, error)
}

// Validator validates DNS messages and chains of trust against configured trust anchors.
type Validator struct {
	anchors  []TrustAnchor
	resolver Resolver
	nowFunc  func() time.Time
}

// NewValidator creates a DNSSEC validator with configured trust anchors and an optional resolver.
func NewValidator(anchors []TrustAnchor, resolver Resolver) *Validator {
	return &Validator{
		anchors:  anchors,
		resolver: resolver,
		nowFunc:  time.Now,
	}
}

// SetTime overrides the validation time for deterministic testing.
func (v *Validator) SetTime(at time.Time) {
	v.nowFunc = func() time.Time { return at }
}

// ValidateResponseWithKeys validates an answer or negative response against known,
// authenticated zone DNSKEYs without performing network queries.
func (v *Validator) ValidateResponseWithKeys(
	qname string,
	qtype uint16,
	msg *dns.Msg,
	zone string,
	zoneKeys []*dns.DNSKEY,
) Result {
	at := v.nowFunc()
	zone = dns.Fqdn(zone)
	query := dns.Fqdn(qname)

	if msg == nil {
		return Result{
			Status: StatusBogus,
			Reason: "DNS response message is nil",
			Zone:   zone,
		}
	}

	// Case 1: Positive response with Answer records
	if len(msg.Answer) > 0 {
		return v.validatePositiveResponse(query, qtype, msg, zone, zoneKeys, at)
	}

	// Case 2: Name Error (NXDOMAIN)
	if msg.Rcode == dns.RcodeNameError {
		return v.validateNXDOMAINResponse(query, msg, zone, zoneKeys, at)
	}

	// Case 3: No Data (NODATA / NOERROR with empty Answer)
	if msg.Rcode == dns.RcodeSuccess && len(msg.Answer) == 0 {
		return v.validateNODATAResponse(query, qtype, msg, zone, zoneKeys, at)
	}

	return Result{
		Status: StatusIndeterminate,
		Reason: fmt.Sprintf("unsupported DNS response rcode %d for validation", msg.Rcode),
		Zone:   zone,
	}
}

func (v *Validator) validatePositiveResponse(
	query string,
	qtype uint16,
	msg *dns.Msg,
	zone string,
	zoneKeys []*dns.DNSKEY,
	at time.Time,
) Result {
	rrsets, err := GroupRRsets(msg.Answer)
	if err != nil {
		return Result{Status: StatusBogus, Reason: fmt.Sprintf("grouping answer RRsets failed: %v", err), Zone: zone}
	}

	// Find target RRset matching query and qtype
	var targetRRset *RRset
	for i := range rrsets {
		rs := &rrsets[i]
		if strings.EqualFold(rs.Name, query) && rs.Type == qtype {
			targetRRset = rs
			break
		}
	}

	// Handle CNAME if target RRset not directly found
	if targetRRset == nil && qtype != dns.TypeCNAME {
		for i := range rrsets {
			rs := &rrsets[i]
			if strings.EqualFold(rs.Name, query) && rs.Type == dns.TypeCNAME {
				targetRRset = rs
				break
			}
		}
	}

	if targetRRset == nil {
		return Result{
			Status: StatusBogus,
			Reason: fmt.Sprintf("response does not contain answer matching %s %s", query, dns.TypeToString[qtype]),
			Zone:   zone,
		}
	}

	sigs, err := SignaturesForRRset(*targetRRset, msg.Answer)
	if err != nil {
		return Result{Status: StatusBogus, Reason: fmt.Sprintf("locating RRSIG for RRset failed: %v", err), Zone: zone}
	}
	if len(sigs) == 0 {
		return Result{
			Status: StatusBogus,
			Reason: fmt.Sprintf("missing RRSIG for answer RRset %s %s", targetRRset.Name, dns.TypeToString[targetRRset.Type]),
			Zone:   zone,
		}
	}

	if err := VerifyRRset(*targetRRset, sigs, zoneKeys, at); err != nil {
		return Result{
			Status: StatusBogus,
			Reason: fmt.Sprintf("cryptographic signature verification failed: %v", err),
			Zone:   zone,
		}
	}

	// Check wildcard expansion (RFC 4034 Section 3.1.5)
	// If RRSIG.Labels < label count of QNAME, answer was synthesized from a wildcard
	qLabels := len(strings.Split(strings.TrimSuffix(query, "."), "."))
	sig := sigs[0]
	wildcard := false
	if int(sig.Labels) < qLabels {
		wildcard = true
		// Verify wildcard denial proof in authority section
		proofRes := v.validateWildcardProof(query, msg, zone, zoneKeys, at)
		if proofRes.Status != NSECProofProven {
			return Result{
				Status: StatusBogus,
				Reason: fmt.Sprintf("wildcard answer missing valid denial of next closer name: %s", proofRes.Reason),
				Zone:   zone,
			}
		}
	}

	return Result{
		Status:       StatusSecure,
		Reason:       "answer RRset cryptographically verified to zone keys",
		Zone:         zone,
		ProofType:    "positive",
		Wildcard:     wildcard,
		SecureRRsets: []RRset{*targetRRset},
	}
}

func (v *Validator) validateNXDOMAINResponse(
	query string,
	msg *dns.Msg,
	zone string,
	zoneKeys []*dns.DNSKEY,
	at time.Time,
) Result {
	nsecRRsets, nsecSigs := extractNSECFromMessage(msg.Ns)
	if len(nsecRRsets) > 0 {
		proof := ValidateNSECNXDOMAINProof(zone, query, nsecRRsets, nsecSigs, zoneKeys, at)
		switch proof.Status {
		case NSECProofProven:
			return Result{Status: StatusSecure, Reason: proof.Reason, Zone: zone, ProofType: "nsec_nxdomain"}
		case NSECProofInvalid:
			return Result{Status: StatusBogus, Reason: proof.Reason, Zone: zone}
		default:
			return Result{Status: StatusBogus, Reason: "incomplete NSEC NXDOMAIN proof: " + proof.Reason, Zone: zone}
		}
	}

	nsec3RRsets, nsec3Sigs := extractNSEC3FromMessage(msg.Ns)
	if len(nsec3RRsets) > 0 {
		proof := ValidateNSEC3NXDOMAINProof(zone, query, nsec3RRsets, nsec3Sigs, zoneKeys, at)
		switch proof.Status {
		case NSECProofProven:
			return Result{Status: StatusSecure, Reason: proof.Reason, Zone: zone, ProofType: "nsec3_nxdomain"}
		case NSECProofUnsupported:
			return Result{Status: StatusIndeterminate, Reason: proof.Reason, Zone: zone}
		default:
			return Result{Status: StatusBogus, Reason: "invalid NSEC3 NXDOMAIN proof: " + proof.Reason, Zone: zone}
		}
	}

	return Result{
		Status: StatusBogus,
		Reason: "NXDOMAIN response contains no authenticated NSEC or NSEC3 denial proofs",
		Zone:   zone,
	}
}

func (v *Validator) validateNODATAResponse(
	query string,
	qtype uint16,
	msg *dns.Msg,
	zone string,
	zoneKeys []*dns.DNSKEY,
	at time.Time,
) Result {
	nsecRRsets, nsecSigs := extractNSECFromMessage(msg.Ns)
	if len(nsecRRsets) > 0 {
		for i, rs := range nsecRRsets {
			proof := ValidateNSECNoDataProof(zone, query, qtype, rs, nsecSigs[i], zoneKeys, at)
			if proof.Status == NSECProofProven {
				return Result{Status: StatusSecure, Reason: proof.Reason, Zone: zone, ProofType: "nsec_nodata"}
			}
		}
	}

	nsec3RRsets, nsec3Sigs := extractNSEC3FromMessage(msg.Ns)
	if len(nsec3RRsets) > 0 {
		proof := ValidateNSEC3NoDataProof(zone, query, qtype, nsec3RRsets, nsec3Sigs, zoneKeys, at)
		switch proof.Status {
		case NSECProofProven:
			return Result{Status: StatusSecure, Reason: proof.Reason, Zone: zone, ProofType: "nsec3_nodata"}
		case NSECProofUnsupported:
			return Result{Status: StatusIndeterminate, Reason: proof.Reason, Zone: zone}
		default:
			return Result{Status: StatusBogus, Reason: "invalid NSEC3 NODATA proof: " + proof.Reason, Zone: zone}
		}
	}

	return Result{
		Status: StatusBogus,
		Reason: "NODATA response contains no valid NSEC or NSEC3 denial proof",
		Zone:   zone,
	}
}

func (v *Validator) validateWildcardProof(
	query string,
	msg *dns.Msg,
	zone string,
	zoneKeys []*dns.DNSKEY,
	at time.Time,
) NSECProofResult {
	nsecRRsets, _ := extractNSECFromMessage(msg.Ns)
	if len(nsecRRsets) > 0 {
		// NSEC interval covering query
		for _, rs := range nsecRRsets {
			if len(rs.Records) > 0 {
				if nsec, ok := rs.Records[0].(*dns.NSEC); ok {
					if NSECIntervalCovers(rs.Name, nsec.NextDomain, query) {
						return NSECProofResult{Status: NSECProofProven, Reason: "NSEC covers query for wildcard proof"}
					}
				}
			}
		}
	}
	nsec3RRsets, nsec3Sigs := extractNSEC3FromMessage(msg.Ns)
	if len(nsec3RRsets) > 0 {
		verified, err := VerifyNSEC3RRsets(zone, nsec3RRsets, nsec3Sigs, zoneKeys, at)
		if err == nil && len(verified) > 0 {
			first := verified[0].Record
			saltBytes, hexErr := decodeHexSalt(first.Salt)
			if hexErr != nil {
				saltBytes = []byte(first.Salt)
			}
			qHash, err := HashNSEC3Name(query, first.Hash, first.Iterations, saltBytes)
			if err == nil {
				for _, vn := range verified {
					if NSEC3IntervalCovers(vn.OwnerHash, vn.NextHash, qHash) {
						return NSECProofResult{Status: NSECProofProven, Reason: "NSEC3 covers query for wildcard proof"}
					}
				}
			}
		}
	}
	return NSECProofResult{Status: NSECProofNotProven, Reason: "no NSEC or NSEC3 covers next closer name for wildcard expansion"}
}

// Validate validates an answer for qname and qtype, dynamically establishing trust
// from configured trust anchors down to the response zone using the Resolver.
func (v *Validator) Validate(
	ctx context.Context,
	qname string,
	qtype uint16,
	response *dns.Msg,
) Result {
	if len(v.anchors) == 0 {
		return Result{
			Status: StatusIndeterminate,
			Reason: "no DNSSEC trust anchors configured",
		}
	}
	if v.resolver == nil {
		return Result{
			Status: StatusIndeterminate,
			Reason: "dynamic chain resolution requires a resolver",
		}
	}

	query := dns.Fqdn(qname)
	// Find matching trust anchor
	var anchor *TrustAnchor
	for i := range v.anchors {
		a := &v.anchors[i]
		if isWithinZone(a.Zone, query) {
			if anchor == nil || len(a.Zone) > len(anchor.Zone) {
				anchor = a
			}
		}
	}
	if anchor == nil {
		return Result{
			Status: StatusIndeterminate,
			Reason: fmt.Sprintf("no trust anchor configured covering %s", query),
		}
	}

	at := v.nowFunc()
	// Determine target authoritative zone from response signatures or SOA
	targetZone := determineTargetZone(query, response)

	// Fetch anchor DNSKEYs if needed
	anchorZone := dns.Fqdn(anchor.Zone)
	anchorMsg, err := v.resolver.Query(ctx, anchorZone, dns.TypeDNSKEY)
	if err != nil {
		return Result{
			Status: StatusIndeterminate,
			Reason: fmt.Sprintf("failed to query trust anchor %s DNSKEY: %v", anchorZone, err),
			Zone:   anchorZone,
		}
	}
	anchorRRsets, err := GroupRRsets(anchorMsg.Answer)
	if err != nil {
		return Result{Status: StatusBogus, Reason: fmt.Sprintf("invalid anchor DNSKEY message: %v", err), Zone: anchorZone}
	}
	var anchorDNSKEYSet *RRset
	for i := range anchorRRsets {
		if anchorRRsets[i].Type == dns.TypeDNSKEY && strings.EqualFold(anchorRRsets[i].Name, anchorZone) {
			anchorDNSKEYSet = &anchorRRsets[i]
			break
		}
	}
	if anchorDNSKEYSet == nil {
		return Result{Status: StatusBogus, Reason: "trust anchor DNSKEY response contains no DNSKEY RRset", Zone: anchorZone}
	}
	anchorSigs, _ := SignaturesForRRset(*anchorDNSKEYSet, anchorMsg.Answer)
	currentKeys, err := ValidateTrustAnchorDNSKEYSet(*anchorDNSKEYSet, anchorSigs, *anchor, at)
	if err != nil {
		return Result{
			Status: StatusBogus,
			Reason: fmt.Sprintf("trust anchor DNSKEY validation failed: %v", err),
			Zone:   anchorZone,
		}
	}

	currentZone := anchorZone
	// Walk down delegations from anchorZone towards targetZone
	labels := dns.SplitDomainName(targetZone)
	anchorLabels := dns.SplitDomainName(anchorZone)
	if anchorZone == "." {
		anchorLabels = nil
	}

	for i := len(anchorLabels); i < len(labels); i++ {
		candidateCut := dns.Fqdn(strings.Join(labels[len(labels)-1-i:], "."))
		if strings.EqualFold(candidateCut, currentZone) {
			continue
		}

		// Query DS from currentZone
		dsMsg, err := v.resolver.Query(ctx, candidateCut, dns.TypeDS)
		if err != nil {
			return Result{
				Status: StatusIndeterminate,
				Reason: fmt.Sprintf("failed to query DS for %s: %v", candidateCut, err),
				Zone:   currentZone,
			}
		}

		// Check if DS exists in Answer
		dsRRsets, err := GroupRRsets(dsMsg.Answer)
		var dsSet *RRset
		if err == nil {
			for j := range dsRRsets {
				if dsRRsets[j].Type == dns.TypeDS && strings.EqualFold(dsRRsets[j].Name, candidateCut) {
					dsSet = &dsRRsets[j]
					break
				}
			}
		}

		if dsSet == nil {
			// No DS: check for authenticated insecure delegation
			nsecRRsets, nsecSigs := extractNSECFromMessage(dsMsg.Ns)
			if len(nsecRRsets) > 0 {
				for k, nrs := range nsecRRsets {
					proof := ValidateInsecureDelegationNSEC(currentZone, candidateCut, nrs, nsecSigs[k], currentKeys, at)
					if proof.Status == NSECProofProven {
						return Result{
							Status: StatusInsecure,
							Reason: fmt.Sprintf("authenticated unsigned delegation proven at %s (NSEC)", candidateCut),
							Zone:   candidateCut,
						}
					}
				}
			}
			nsec3RRsets, nsec3Sigs := extractNSEC3FromMessage(dsMsg.Ns)
			if len(nsec3RRsets) > 0 {
				proof := ValidateNSEC3InsecureDelegation(currentZone, candidateCut, nsec3RRsets, nsec3Sigs, currentKeys, at)
				if proof.Status == NSECProofProven {
					return Result{
						Status: StatusInsecure,
						Reason: fmt.Sprintf("authenticated unsigned delegation proven at %s (NSEC3 Opt-Out)", candidateCut),
						Zone:   candidateCut,
					}
				}
			}

			// If neither DS nor denial proof exists, delegation cannot be validated
			return Result{
				Status: StatusBogus,
				Reason: fmt.Sprintf("delegation at %s has neither DS nor authenticated denial proof", candidateCut),
				Zone:   currentZone,
			}
		}

		// DS exists: query child DNSKEY
		childDNSKEYMsg, err := v.resolver.Query(ctx, candidateCut, dns.TypeDNSKEY)
		if err != nil {
			return Result{
				Status: StatusIndeterminate,
				Reason: fmt.Sprintf("failed to query child DNSKEY for %s: %v", candidateCut, err),
				Zone:   currentZone,
			}
		}
		childRRsets, err := GroupRRsets(childDNSKEYMsg.Answer)
		if err != nil {
			return Result{Status: StatusBogus, Reason: fmt.Sprintf("invalid child DNSKEY response: %v", err), Zone: candidateCut}
		}
		var childDNSKEYSet *RRset
		for j := range childRRsets {
			if childRRsets[j].Type == dns.TypeDNSKEY && strings.EqualFold(childRRsets[j].Name, candidateCut) {
				childDNSKEYSet = &childRRsets[j]
				break
			}
		}
		if childDNSKEYSet == nil {
			return Result{Status: StatusBogus, Reason: fmt.Sprintf("no DNSKEY RRset in child zone %s answer", candidateCut), Zone: candidateCut}
		}

		dsSigs, _ := SignaturesForRRset(*dsSet, dsMsg.Answer)
		matched, err := ValidateDelegationDS(currentZone, *dsSet, dsSigs, currentKeys, extractDNSKEYs(*childDNSKEYSet), at)
		if err != nil {
			return Result{Status: StatusBogus, Reason: fmt.Sprintf("DS validation failed for %s: %v", candidateCut, err), Zone: currentZone}
		}

		childSigs, _ := SignaturesForRRset(*childDNSKEYSet, childDNSKEYMsg.Answer)
		currentKeys, err = ValidateChildDNSKEYSet(candidateCut, *childDNSKEYSet, childSigs, matched, at)
		if err != nil {
			return Result{Status: StatusBogus, Reason: fmt.Sprintf("child DNSKEY validation failed for %s: %v", candidateCut, err), Zone: candidateCut}
		}
		currentZone = candidateCut
	}

	// Now validate the actual response message using authenticated currentKeys
	res := v.ValidateResponseWithKeys(query, qtype, response, currentZone, currentKeys)
	res.TrustAnchor = anchorZone
	return res
}

func determineTargetZone(qname string, msg *dns.Msg) string {
	if msg == nil {
		return getParentDomain(qname)
	}
	// Check answer RRSIG
	for _, rr := range msg.Answer {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.SignerName != "" {
			return dns.Fqdn(sig.SignerName)
		}
	}
	// Check authority RRSIG or SOA
	for _, rr := range msg.Ns {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.SignerName != "" {
			return dns.Fqdn(sig.SignerName)
		}
		if soa, ok := rr.(*dns.SOA); ok && soa.Hdr.Name != "" {
			return dns.Fqdn(soa.Hdr.Name)
		}
	}
	return getParentDomain(qname)
}

func extractNSECFromMessage(rrs []dns.RR) ([]RRset, [][]*dns.RRSIG) {
	grouped, err := GroupRRsets(rrs)
	if err != nil {
		return nil, nil
	}
	var nsecs []RRset
	var sigs [][]*dns.RRSIG
	for _, rs := range grouped {
		if rs.Type == dns.TypeNSEC {
			s, _ := SignaturesForRRset(rs, rrs)
			nsecs = append(nsecs, rs)
			sigs = append(sigs, s)
		}
	}
	return nsecs, sigs
}

func extractNSEC3FromMessage(rrs []dns.RR) ([]RRset, [][]*dns.RRSIG) {
	grouped, err := GroupRRsets(rrs)
	if err != nil {
		return nil, nil
	}
	var nsec3s []RRset
	var sigs [][]*dns.RRSIG
	for _, rs := range grouped {
		if rs.Type == dns.TypeNSEC3 {
			s, _ := SignaturesForRRset(rs, rrs)
			nsec3s = append(nsec3s, rs)
			sigs = append(sigs, s)
		}
	}
	return nsec3s, sigs
}
