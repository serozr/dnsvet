package dnssec

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var ErrNoDelegationKey = errors.New("no child DNSKEY matches the authenticated DS RRset")

// ValidateDelegationDS authenticates a child's DS RRset with the parent zone's
// already-authenticated DNSKEYs, then matches those DS records to the supplied
// child DNSKEYs. DNSKEYs with Protocol values other than 3 are ignored.
func ValidateDelegationDS(
	parentZone string,
	dsRRset RRset,
	signatures []*dns.RRSIG,
	parentKeys []*dns.DNSKEY,
	childKeys []*dns.DNSKEY,
	at time.Time,
) ([]*dns.DNSKEY, error) {
	if parentZone == "" {
		return nil, errors.New("parent zone is empty")
	}
	if len(dsRRset.Records) == 0 {
		return nil, errors.New("DS RRset is empty")
	}
	if dsRRset.Type != dns.TypeDS {
		return nil, fmt.Errorf("delegation validation requires a DS RRset, got type %d", dsRRset.Type)
	}
	if len(parentKeys) == 0 {
		return nil, errors.New("authenticated parent DNSKEYs are required")
	}
	if len(childKeys) == 0 {
		return nil, errors.New("child DNSKEYs are required")
	}

	parent := dns.Fqdn(parentZone)
	child := dns.Fqdn(dsRRset.Name)
	if !isChildZone(parent, child) {
		return nil, fmt.Errorf("zone %q is not a child delegation of parent %q", child, parent)
	}

	usableParentKeys := make([]*dns.DNSKEY, 0, len(parentKeys))
	for i, key := range parentKeys {
		if key == nil {
			return nil, fmt.Errorf("parent DNSKEY at index %d is nil", i)
		}
		if key.Hdr.Class != dsRRset.Class ||
			!strings.EqualFold(dns.Fqdn(key.Hdr.Name), parent) {
			return nil, fmt.Errorf("parent DNSKEY at index %d does not belong to parent zone %q", i, parent)
		}
		if key.Protocol == 3 {
			usableParentKeys = append(usableParentKeys, key)
		}
	}
	if len(usableParentKeys) == 0 {
		return nil, errors.New("no usable parent DNSKEYs with protocol 3")
	}

	for i, record := range dsRRset.Records {
		ds, ok := record.(*dns.DS)
		if !ok {
			return nil, fmt.Errorf("DS RRset record at index %d is not a DS record", i)
		}
		if ds.Hdr.Class != dsRRset.Class ||
			!strings.EqualFold(dns.Fqdn(ds.Hdr.Name), child) {
			return nil, fmt.Errorf("DS record at index %d does not belong to child zone %q", i, child)
		}
	}

	if err := VerifyRRset(dsRRset, signatures, usableParentKeys, at); err != nil {
		return nil, fmt.Errorf("parent DS RRset signature verification failed: %w", err)
	}

	// RFC 4509 section 3 recommends ignoring SHA-1 DS records when
	// the authenticated DS RRset also contains SHA-256 DS records.
	// Verify the complete RRset above, then apply this preference only
	// to the DS-to-DNSKEY matching stage.
	// Prefer SHA-256 over SHA-1 only for the same key identity.
	hasSHA256ForKey := make(map[[2]uint16]bool)
	for _, record := range dsRRset.Records {
		ds := record.(*dns.DS)
		if ds.DigestType == dns.SHA256 {
			hasSHA256ForKey[[2]uint16{ds.KeyTag, uint16(ds.Algorithm)}] = true
		}
	}

	matched := make([]*dns.DNSKEY, 0)
	unsupportedDigests := 0
	supportedDigests := 0
	for _, record := range dsRRset.Records {
		ds := record.(*dns.DS)
		keyID := [2]uint16{ds.KeyTag, uint16(ds.Algorithm)}
		if ds.DigestType == dns.SHA1 && hasSHA256ForKey[keyID] {
			continue
		}
		for _, key := range childKeys {
			if key == nil || key.Protocol != 3 {
				continue
			}
			if key.Hdr.Class != dsRRset.Class ||
				!strings.EqualFold(dns.Fqdn(key.Hdr.Name), child) {
				continue
			}
			ok, err := MatchDNSKEYToDS(key, ds)
			if err != nil {
				if errors.Is(err, ErrUnsupportedDigest) {
					unsupportedDigests++
					continue
				}
				return nil, err
			}
			supportedDigests++
			if ok && !containsDNSKEY(matched, key) {
				matched = append(matched, key)
			}
		}
	}

	if len(matched) > 0 {
		return matched, nil
	}
	if supportedDigests == 0 && unsupportedDigests > 0 {
		return nil, fmt.Errorf("%w: all DS digest types are unsupported", ErrUnsupportedDigest)
	}
	return nil, ErrNoDelegationKey
}

func isChildZone(parent, child string) bool {
	parent = strings.ToLower(dns.Fqdn(parent))
	child = strings.ToLower(dns.Fqdn(child))
	if parent == "." {
		return child != "." && strings.Count(strings.TrimSuffix(child, "."), ".") == 0
	}
	if child == parent || !strings.HasSuffix(child, "."+parent) {
		return false
	}
	prefix := strings.TrimSuffix(child, parent)
	return strings.HasSuffix(prefix, ".") && strings.Count(strings.TrimSuffix(prefix, "."), ".") == 0
}

func containsDNSKEY(keys []*dns.DNSKEY, candidate *dns.DNSKEY) bool {
	for _, key := range keys {
		if sameDNSKEY(key, candidate) {
			return true
		}
	}
	return false
}
