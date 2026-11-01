package dnssec

import (
	"strings"
	"unicode"
)

// NSECIntervalCovers reports whether name is strictly covered by the
// circular canonical DNSSEC interval (owner, nextDomain) represented by an
// NSEC record. DNSSEC canonical ordering compares labels from right to left
// and compares each label as unsigned octets after ASCII-only case folding.
//
// This helper checks interval membership only. It does not authenticate the
// NSEC RR, validate its bitmap, or enforce that name belongs to a particular
// zone; callers must perform those checks separately.
func NSECIntervalCovers(owner, nextDomain, name string) bool {
	if !validNSECIntervalName(owner) || !validNSECIntervalName(nextDomain) || !validNSECIntervalName(name) {
		return false
	}
	ownerToNext := canonicalNameOrder(owner, nextDomain)
	ownerToName := canonicalNameOrder(owner, name)
	nameToNext := canonicalNameOrder(name, nextDomain)

	// A single-record zone has one NSEC whose next name is its own owner.
	if ownerToNext == 0 {
		return ownerToName != 0
	}
	// NSEC intervals are open: neither endpoint is covered.
	if ownerToName == 0 || nameToNext == 0 {
		return false
	}
	if ownerToNext < 0 {
		return ownerToName < 0 && nameToNext < 0
	}
	// The interval wraps around the end of canonical DNS name order.
	return ownerToName < 0 || nameToNext < 0
}

// validNSECIntervalName rejects raw whitespace and control characters in
// presentation-format names. Arbitrary label octets must be escaped.
func validNSECIntervalName(name string) bool {
	if !validDNSName(name) {
		return false
	}
	return !strings.ContainsFunc(name, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	})
}
