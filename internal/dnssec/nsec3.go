package dnssec

import (
	"crypto/sha1"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	// MaxNSEC3Iterations is the maximum allowed iteration count per RFC 9276 Section 3.
	MaxNSEC3Iterations = 100

	// NSEC3OptOut is the Opt-Out flag bit per RFC 5155 Section 3.1.2.
	NSEC3OptOut = 0x01
)

var (
	ErrUnsupportedNSEC3Algorithm = errors.New("unsupported NSEC3 hash algorithm (only SHA-1 is supported)")
	ErrExcessiveNSEC3Iterations  = errors.New("excessive NSEC3 iteration count exceeds RFC 9276 safety limit (100)")
)

var base32Hex = base32.HexEncoding.WithPadding(base32.NoPadding)

// HashNSEC3Name calculates the NSEC3 hashed owner name for a domain name
// in canonical wire format using RFC 5155 Section 5 algorithm.
func HashNSEC3Name(name string, algorithm uint8, iterations uint16, salt []byte) (string, error) {
	if algorithm != 1 {
		return "", fmt.Errorf("%w: got algorithm %d", ErrUnsupportedNSEC3Algorithm, algorithm)
	}
	if iterations > MaxNSEC3Iterations {
		return "", fmt.Errorf("%w: %d > %d", ErrExcessiveNSEC3Iterations, iterations, MaxNSEC3Iterations)
	}
	wire, err := canonicalWireDomainName(name)
	if err != nil {
		return "", err
	}

	h := sha1.New()
	h.Write(wire)
	h.Write(salt)
	digest := h.Sum(nil)

	for i := uint16(0); i < iterations; i++ {
		h.Reset()
		h.Write(digest)
		h.Write(salt)
		digest = h.Sum(nil)
	}

	return strings.ToLower(base32Hex.EncodeToString(digest)), nil
}

func canonicalWireDomainName(name string) ([]byte, error) {
	name = strings.ToLower(dns.Fqdn(name))
	wire := make([]byte, 256)
	n, err := dns.PackDomainName(name, wire, 0, nil, false)
	if err != nil {
		return nil, fmt.Errorf("canonical wire packing failed for %q: %w", name, err)
	}
	return wire[:n], nil
}

// NSEC3IntervalCovers reports whether targetHash is strictly covered by
// the circular interval (ownerHash, nextHash) per RFC 5155 Section 8.
func NSEC3IntervalCovers(ownerHash, nextHash, targetHash string) bool {
	owner := strings.ToLower(strings.TrimSpace(ownerHash))
	next := strings.ToLower(strings.TrimSpace(nextHash))
	target := strings.ToLower(strings.TrimSpace(targetHash))

	if owner == "" || next == "" || target == "" {
		return false
	}
	if owner == next {
		// Single-record zone: covers every other hash in the zone
		return target != owner
	}
	if target == owner || target == next {
		// Open interval: endpoints are not covered
		return false
	}
	if owner < next {
		return target > owner && target < next
	}
	// Wrap-around at the end of the hashed space
	return target > owner || target < next
}

// VerifiedNSEC3 contains a cryptographically verified NSEC3 record and its parsed hashes.
type VerifiedNSEC3 struct {
	Record    *dns.NSEC3
	OwnerHash string
	NextHash  string
	Zone      string
}

// VerifyNSEC3RRsets cryptographically verifies a list of NSEC3 RRsets against zoneKeys.
func VerifyNSEC3RRsets(
	zone string,
	rrsets []RRset,
	signatures [][]*dns.RRSIG,
	zoneKeys []*dns.DNSKEY,
	at time.Time,
) ([]VerifiedNSEC3, error) {
	if len(rrsets) == 0 {
		return nil, errors.New("no NSEC3 RRsets provided")
	}
	if len(rrsets) != len(signatures) {
		return nil, errors.New("mismatched NSEC3 RRsets and signatures counts")
	}
	if len(zoneKeys) == 0 {
		return nil, errors.New("zone DNSKEYs are required for NSEC3 verification")
	}
	zone = dns.Fqdn(zone)

	verified := make([]VerifiedNSEC3, 0, len(rrsets))
	for i, rrset := range rrsets {
		if err := validateRRsetMetadata(rrset); err != nil {
			return nil, fmt.Errorf("NSEC3 RRset %d metadata invalid: %w", i, err)
		}
		if rrset.Type != dns.TypeNSEC3 || rrset.Class != dns.ClassINET || len(rrset.Records) != 1 {
			return nil, fmt.Errorf("NSEC3 RRset %d must contain exactly one IN NSEC3 record", i)
		}
		nsec3, ok := rrset.Records[0].(*dns.NSEC3)
		if !ok || nsec3 == nil {
			return nil, fmt.Errorf("record at index %d is not *dns.NSEC3", i)
		}

		// Owner name must be <hash>.<zone>
		ownerFqdn := dns.Fqdn(rrset.Name)
		if !isWithinZone(zone, ownerFqdn) {
			return nil, fmt.Errorf("NSEC3 owner %q is outside zone %q", ownerFqdn, zone)
		}
		labels := strings.Split(strings.TrimSuffix(ownerFqdn, "."), ".")
		zoneLabels := strings.Split(strings.TrimSuffix(zone, "."), ".")
		if len(labels) != len(zoneLabels)+1 {
			return nil, fmt.Errorf("NSEC3 owner %q does not match <hash>.%s format", ownerFqdn, zone)
		}
		ownerHash := strings.ToLower(labels[0])
		nextHash := strings.ToLower(nsec3.NextDomain)

		if err := VerifyRRset(rrset, signatures[i], zoneKeys, at); err != nil {
			return nil, fmt.Errorf("NSEC3 RRset %d signature verification failed: %w", i, err)
		}

		verified = append(verified, VerifiedNSEC3{
			Record:    nsec3,
			OwnerHash: ownerHash,
			NextHash:  nextHash,
			Zone:      zone,
		})
	}
	return verified, nil
}

// ValidateNSEC3NoDataProof validates an NSEC3 authenticated denial of existence
// for a NODATA response (QNAME exists, but QTYPE does not) per RFC 5155 Section 8.5.
func ValidateNSEC3NoDataProof(
	zone string,
	qname string,
	qtype uint16,
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
	unsupported := func(reason string) NSECProofResult {
		return NSECProofResult{Status: NSECProofUnsupported, Reason: reason}
	}

	if !validDNSName(zone) || !validDNSName(qname) {
		return invalid("zone or query name is invalid")
	}
	if qtype == 0 {
		return invalid("query type must not be zero")
	}
	zone = dns.Fqdn(zone)
	query := dns.Fqdn(qname)
	if !isWithinZone(zone, query) {
		return invalid("query name is outside the supplied zone")
	}

	verified, err := VerifyNSEC3RRsets(zone, rrsets, signatures, zoneKeys, at)
	if err != nil {
		return invalid(fmt.Sprintf("NSEC3 verification failed: %v", err))
	}

	// 1. Exact match check
	first := verified[0].Record
	saltBytes, hexErr := decodeHexSalt(first.Salt)
	if hexErr != nil {
		saltBytes = []byte(first.Salt)
	}

	qHash, err := HashNSEC3Name(query, first.Hash, first.Iterations, saltBytes)
	if err != nil {
		if errors.Is(err, ErrUnsupportedNSEC3Algorithm) || errors.Is(err, ErrExcessiveNSEC3Iterations) {
			return unsupported(err.Error())
		}
		return invalid(fmt.Sprintf("hashing query name failed: %v", err))
	}

	for _, v := range verified {
		if strings.EqualFold(v.OwnerHash, qHash) {
			// Found exact match NSEC3
			hasQType := false
			hasCNAME := false
			for _, t := range v.Record.TypeBitMap {
				if t == qtype {
					hasQType = true
				}
				if t == dns.TypeCNAME {
					hasCNAME = true
				}
			}
			if hasQType {
				return invalid(fmt.Sprintf("NSEC3 bitmap contains queried type %s; contradicts NODATA", dns.TypeToString[qtype]))
			}
			if hasCNAME {
				return invalid("NSEC3 bitmap contains CNAME; contradicts NODATA")
			}
			return NSECProofResult{
				Status: NSECProofProven,
				Reason: fmt.Sprintf("exact match NSEC3 %s proves type %s does not exist at %s", v.OwnerHash, dns.TypeToString[qtype], query),
			}
		}
	}

	// 2. Wildcard NODATA check
	// If exact match not found, check closest encloser and wildcard match
	ce, nextCloser := findClosestEncloserAndNextCloser(zone, query, verified, first.Hash, first.Iterations, saltBytes)
	if ce != "" && nextCloser != "" {
		ncHash, _ := HashNSEC3Name(nextCloser, first.Hash, first.Iterations, saltBytes)
		wildcard := dns.Fqdn("*." + ce)
		wHash, _ := HashNSEC3Name(wildcard, first.Hash, first.Iterations, saltBytes)

		coveredNC := false
		matchedWildcard := false
		for _, v := range verified {
			if NSEC3IntervalCovers(v.OwnerHash, v.NextHash, ncHash) {
				coveredNC = true
			}
			if strings.EqualFold(v.OwnerHash, wHash) {
				hasQType, hasCNAME := false, false
				for _, t := range v.Record.TypeBitMap {
					if t == qtype {
						hasQType = true
					}
					if t == dns.TypeCNAME {
						hasCNAME = true
					}
				}
				if !hasQType && !hasCNAME {
					matchedWildcard = true
				}
			}
		}
		if coveredNC && matchedWildcard {
			return NSECProofResult{
				Status: NSECProofProven,
				Reason: fmt.Sprintf("wildcard NODATA proven by NSEC3 for closest encloser %s", ce),
			}
		}
	}

	return notProven(fmt.Sprintf("no NSEC3 record proves NODATA for %s type %s", query, dns.TypeToString[qtype]))
}

// ValidateNSEC3NXDOMAINProof validates an NSEC3 authenticated denial of existence
// for a non-existent name (NXDOMAIN) according to RFC 5155 Section 8.4.
func ValidateNSEC3NXDOMAINProof(
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
	unsupported := func(reason string) NSECProofResult {
		return NSECProofResult{Status: NSECProofUnsupported, Reason: reason}
	}

	if !validDNSName(zone) || !validDNSName(qname) {
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

	verified, err := VerifyNSEC3RRsets(zone, rrsets, signatures, zoneKeys, at)
	if err != nil {
		return invalid(fmt.Sprintf("NSEC3 verification failed: %v", err))
	}

	first := verified[0].Record
	saltBytes, hexErr := decodeHexSalt(first.Salt)
	if hexErr != nil {
		saltBytes = []byte(first.Salt)
	}

	// 1. Closest encloser (CE) and next closer (NC)
	ce, nextCloser := findClosestEncloserAndNextCloser(zone, query, verified, first.Hash, first.Iterations, saltBytes)
	if ce == "" || nextCloser == "" {
		return notProven("could not establish authenticated closest encloser for NSEC3 NXDOMAIN proof")
	}

	ncHash, err := HashNSEC3Name(nextCloser, first.Hash, first.Iterations, saltBytes)
	if err != nil {
		if errors.Is(err, ErrUnsupportedNSEC3Algorithm) || errors.Is(err, ErrExcessiveNSEC3Iterations) {
			return unsupported(err.Error())
		}
		return invalid(fmt.Sprintf("hashing next closer name failed: %v", err))
	}

	// 2. Cover next closer name
	coveredNC := false
	for _, v := range verified {
		if NSEC3IntervalCovers(v.OwnerHash, v.NextHash, ncHash) {
			coveredNC = true
			break
		}
	}
	if !coveredNC {
		return notProven(fmt.Sprintf("no NSEC3 covers next closer hash %s for %s", ncHash, nextCloser))
	}

	// 3. Cover wildcard at closest encloser (*.<CE>)
	wildcard := dns.Fqdn("*." + ce)
	wHash, err := HashNSEC3Name(wildcard, first.Hash, first.Iterations, saltBytes)
	if err != nil {
		return invalid(fmt.Sprintf("hashing wildcard name failed: %v", err))
	}

	// Contradiction: if wildcard matches an NSEC3 owner, wildcard exists!
	for _, v := range verified {
		if strings.EqualFold(v.OwnerHash, wHash) {
			return invalid(fmt.Sprintf("NSEC3 owner matches wildcard %s; contradicts NXDOMAIN", wildcard))
		}
	}

	coveredWildcard := false
	for _, v := range verified {
		if NSEC3IntervalCovers(v.OwnerHash, v.NextHash, wHash) {
			coveredWildcard = true
			break
		}
	}
	if !coveredWildcard {
		return notProven(fmt.Sprintf("no NSEC3 covers wildcard hash %s for %s", wHash, wildcard))
	}

	return NSECProofResult{
		Status: NSECProofProven,
		Reason: fmt.Sprintf("NSEC3 proves NXDOMAIN for %s (CE=%s, NC covered, wildcard covered)", query, ce),
	}
}

// ValidateNSEC3InsecureDelegation proves an unsigned delegation (DS absence)
// at delegationName per RFC 5155 Section 8.5 (exact match without DS or Opt-Out).
func ValidateNSEC3InsecureDelegation(
	parentZone string,
	delegationName string,
	rrsets []RRset,
	signatures [][]*dns.RRSIG,
	parentKeys []*dns.DNSKEY,
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

	if !validDNSName(parentZone) || !validDNSName(delegationName) {
		return invalid("parent or delegation name is invalid")
	}
	parent := dns.Fqdn(parentZone)
	child := dns.Fqdn(delegationName)
	if !isChildZone(parent, child) {
		return invalid("delegation is not below the supplied parent zone")
	}

	verified, err := VerifyNSEC3RRsets(parent, rrsets, signatures, parentKeys, at)
	if err != nil {
		return invalid(fmt.Sprintf("NSEC3 verification failed: %v", err))
	}

	first := verified[0].Record
	saltBytes, hexErr := decodeHexSalt(first.Salt)
	if hexErr != nil {
		saltBytes = []byte(first.Salt)
	}

	childHash, err := HashNSEC3Name(child, first.Hash, first.Iterations, saltBytes)
	if err != nil {
		if errors.Is(err, ErrUnsupportedNSEC3Algorithm) || errors.Is(err, ErrExcessiveNSEC3Iterations) {
			return unsupported(err.Error())
		}
		return invalid(fmt.Sprintf("hashing delegation name failed: %v", err))
	}

	// 1. Exact match check: NSEC3 owner matches childHash
	for _, v := range verified {
		if strings.EqualFold(v.OwnerHash, childHash) {
			hasNS, hasDS, hasSOA := false, false, false
			for _, typ := range v.Record.TypeBitMap {
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
				return invalid("delegation-point NSEC3 bitmap does not contain NS")
			}
			if hasSOA {
				return invalid("delegation-point NSEC3 bitmap contains SOA")
			}
			if hasDS {
				return notProven("delegation-point NSEC3 bitmap contains DS")
			}
			return NSECProofResult{
				Status: NSECProofProven,
				Reason: "delegation-point NSEC3 bitmap omits DS and SOA",
			}
		}
	}

	// 2. Opt-Out check: an NSEC3 covering childHash with Opt-Out flag set
	for _, v := range verified {
		if NSEC3IntervalCovers(v.OwnerHash, v.NextHash, childHash) {
			if v.Record.Flags&NSEC3OptOut != 0 {
				return NSECProofResult{
					Status: NSECProofProven,
					Reason: "delegation is covered by parent NSEC3 with Opt-Out flag set",
				}
			}
			return notProven("covering NSEC3 does not have Opt-Out flag set")
		}
	}

	return notProven("no NSEC3 record proves DS absence at delegation")
}

func findClosestEncloserAndNextCloser(
	zone string,
	query string,
	verified []VerifiedNSEC3,
	alg uint8,
	iter uint16,
	salt []byte,
) (string, string) {
	curr := query
	var nextCloser string
	for {
		parent := getParentDomain(curr)
		if parent == "" || !isWithinZone(zone, parent) {
			break
		}
		// Hash parent
		pHash, err := HashNSEC3Name(parent, alg, iter, salt)
		if err == nil {
			for _, v := range verified {
				if strings.EqualFold(v.OwnerHash, pHash) {
					return parent, curr
				}
			}
		}
		nextCloser = curr
		curr = parent
	}
	// Fallback: apex zone
	return zone, nextCloser
}

func decodeHexSalt(saltHex string) ([]byte, error) {
	if saltHex == "-" || saltHex == "" {
		return nil, nil
	}
	if len(saltHex)%2 != 0 {
		return nil, errors.New("odd length hex salt")
	}
	salt := make([]byte, len(saltHex)/2)
	for i := 0; i < len(salt); i++ {
		b, err := parseHexByte(saltHex[2*i : 2*i+2])
		if err != nil {
			return nil, err
		}
		salt[i] = b
	}
	return salt, nil
}

func parseHexByte(s string) (byte, error) {
	var val byte
	for _, ch := range s {
		val <<= 4
		switch {
		case ch >= '0' && ch <= '9':
			val |= byte(ch - '0')
		case ch >= 'a' && ch <= 'f':
			val |= byte(ch - 'a' + 10)
		case ch >= 'A' && ch <= 'F':
			val |= byte(ch - 'A' + 10)
		default:
			return 0, fmt.Errorf("invalid hex char %c", ch)
		}
	}
	return val, nil
}
