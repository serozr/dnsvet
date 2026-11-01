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
// child DNSKEYs. The returned keys are authenticated by the parent-signed DS
// RRset, but the child's DNSKEY RRset signature must still be verified before
// treating the complete child DNSKEY set as trusted.
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

	for i, key := range parentKeys {
		if key == nil {
			return nil, fmt.Errorf("parent DNSKEY at index %d is nil", i)
		}
		if key.Hdr.Class != dsRRset.Class ||
			!strings.EqualFold(dns.Fqdn(key.Hdr.Name), parent) ||
			key.Protocol != 3 {
			return nil, fmt.Errorf("parent DNSKEY at index %d does not belong to parent zone %q", i, parent)
		}
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

	if err := VerifyRRset(dsRRset, signatures, parentKeys, at); err != nil {
		return nil, fmt.Errorf("parent DS RRset signature verification failed: %w", err)
	}

	matched := make([]*dns.DNSKEY, 0)
	unsupportedDigests := 0
	supportedDigests := 0
	for _, record := range dsRRset.Records {
		ds := record.(*dns.DS)
		for _, key := range childKeys {
			if key == nil {
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
		return child != "." && strings.HasSuffix(child, ".")
	}
	return child != parent && strings.HasSuffix(child, "."+parent)
}

func containsDNSKEY(keys []*dns.DNSKEY, candidate *dns.DNSKEY) bool {
	for _, key := range keys {
		if sameDNSKEY(key, candidate) {
			return true
		}
	}
	return false
}
