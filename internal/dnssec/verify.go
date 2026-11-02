package dnssec

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var (
	ErrNoSignatures            = errors.New("RRset has no signatures")
	ErrNoMatchingKey           = errors.New("no DNSKEY matches any RRSIG")
	ErrSignatureNotValidAtTime = errors.New("no RRSIG is valid at the supplied time")
	ErrNoValidSignature        = errors.New("no RRSIG cryptographically validates")
)

// VerifyRRset validates an RRset against its RRSIG records and candidate DNSKEYs.
// It checks signature validity periods separately from cryptographic verification.
// DNSKEYs with a Protocol value other than 3 are ignored as signing keys.
// This verifies only the supplied key/signature relationship; it does not build
// or authenticate the DNSSEC chain from a configured trust anchor.
func VerifyRRset(rrset RRset, signatures []*dns.RRSIG, keys []*dns.DNSKEY, at time.Time) error {
	if len(rrset.Records) == 0 {
		return errors.New("cannot verify an empty RRset")
	}
	if len(rrset.Records) > MaxRRsetRecords {
		return fmt.Errorf("RRset record count %d exceeds maximum %d", len(rrset.Records), MaxRRsetRecords)
	}
	if len(signatures) > MaxRRsetSignatures {
		return fmt.Errorf("signature count %d exceeds maximum %d", len(signatures), MaxRRsetSignatures)
	}
	if len(keys) > MaxValidationKeys {
		return fmt.Errorf("validation key count %d exceeds maximum %d", len(keys), MaxValidationKeys)
	}
	if at.IsZero() {
		return errors.New("verification time must be specified")
	}

	owner := dns.Fqdn(rrset.Name)
	seen := make(map[string]struct{}, len(rrset.Records))
	for i, record := range rrset.Records {
		if record == nil {
			return fmt.Errorf("RRset record at index %d is nil", i)
		}
		header := record.Header()
		if header == nil {
			return fmt.Errorf("RRset record at index %d has no DNS header", i)
		}
		if !strings.EqualFold(dns.Fqdn(header.Name), owner) ||
			header.Class != rrset.Class || header.Rrtype != rrset.Type {
			return fmt.Errorf("RRset record at index %d does not match RRset owner, class, and type", i)
		}
		key := canonicalRRKey(record)
		if _, ok := seen[key]; ok {
			return fmt.Errorf("RRset contains duplicate record at index %d", i)
		}
		seen[key] = struct{}{}
	}

	if len(signatures) == 0 {
		return ErrNoSignatures
	}

	matchedKey := false
	validTime := false
	var lastErr error

	for i, signature := range signatures {
		if signature == nil {
			lastErr = fmt.Errorf("RRSIG at index %d is nil", i)
			continue
		}
		if !strings.EqualFold(dns.Fqdn(signature.Hdr.Name), owner) ||
			signature.Hdr.Class != rrset.Class ||
			signature.TypeCovered != rrset.Type {
			lastErr = fmt.Errorf("RRSIG at index %d does not cover the supplied RRset", i)
			continue
		}
		if !signature.ValidityPeriod(at) {
			continue
		}
		validTime = true

		for _, key := range keys {
			if key == nil || key.Protocol != 3 {
				continue
			}
			if signature.KeyTag != key.KeyTag() ||
				signature.Algorithm != key.Algorithm ||
				!strings.EqualFold(dns.Fqdn(signature.SignerName), dns.Fqdn(key.Hdr.Name)) {
				continue
			}
			matchedKey = true
			if err := signature.Verify(key, rrset.Records); err == nil {
				return nil
			} else {
				lastErr = err
			}
		}
	}

	if !validTime {
		return ErrSignatureNotValidAtTime
	}
	if !matchedKey {
		return ErrNoMatchingKey
	}
	if lastErr != nil {
		return fmt.Errorf("%w: %v", ErrNoValidSignature, lastErr)
	}
	return ErrNoValidSignature
}
