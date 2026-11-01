package dnssec

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// TrustAnchor is a locally configured DNSKEY trusted independently of DNS.
// DNSKEY is retained for backwards compatibility. DNSKEYs allows multiple
// independently provisioned keys for rollover and overlapping trust periods.
// At least one configured key must authenticate the supplied DNSKEY RRset.
type TrustAnchor struct {
	Zone   string
	DNSKEY *dns.DNSKEY
	DNSKEYs []*dns.DNSKEY
}

// ValidateTrustAnchorDNSKEYSet authenticates a zone's DNSKEY RRset using one
// or more explicitly configured DNSKEY trust anchors. It returns usable zone
// keys only after the RRset signature has been verified by a configured key
// that is present in the RRset. Non-Protocol-3 records remain in the signed
// RRset but are not returned as usable keys.
func ValidateTrustAnchorDNSKEYSet(
	rrset RRset,
	signatures []*dns.RRSIG,
	anchor TrustAnchor,
	at time.Time,
) ([]*dns.DNSKEY, error) {
	if anchor.Zone == "" {
		return nil, errors.New("trust anchor zone is empty")
	}
	if len(rrset.Records) == 0 {
		return nil, errors.New("DNSKEY RRset is empty")
	}
	if rrset.Type != dns.TypeDNSKEY {
		return nil, fmt.Errorf("trust anchor validation requires a DNSKEY RRset, got type %d", rrset.Type)
	}

	zone := dns.Fqdn(anchor.Zone)
	if !strings.EqualFold(dns.Fqdn(rrset.Name), zone) {
		return nil, errors.New("trust anchor zone does not match DNSKEY RRset")
	}

	configured := make([]*dns.DNSKEY, 0, len(anchor.DNSKEYs)+1)
	if anchor.DNSKEY != nil {
		configured = append(configured, anchor.DNSKEY)
	}
	configured = append(configured, anchor.DNSKEYs...)
	if len(configured) == 0 {
		return nil, errors.New("no trust anchor DNSKEYs configured")
	}

	for i, key := range configured {
		if key == nil {
			return nil, fmt.Errorf("trust anchor DNSKEY at index %d is nil", i)
		}
		if key.Protocol != 3 {
			return nil, fmt.Errorf("invalid trust anchor DNSKEY protocol %d at index %d: want 3", key.Protocol, i)
		}
		if key.Hdr.Rrtype != dns.TypeDNSKEY ||
			key.Hdr.Class != rrset.Class ||
			!strings.EqualFold(dns.Fqdn(key.Hdr.Name), zone) {
			return nil, fmt.Errorf("trust anchor DNSKEY at index %d metadata does not match the anchored zone and RRset", i)
		}
	}

	presentAnchors := make([]*dns.DNSKEY, 0, len(configured))
	authenticatedKeys := make([]*dns.DNSKEY, 0, len(rrset.Records))
	for i, record := range rrset.Records {
		key, ok := record.(*dns.DNSKEY)
		if !ok {
			return nil, fmt.Errorf("DNSKEY RRset record at index %d is not a DNSKEY", i)
		}
		if key.Hdr.Class != rrset.Class ||
			!strings.EqualFold(dns.Fqdn(key.Hdr.Name), zone) {
			return nil, fmt.Errorf("DNSKEY at index %d does not belong to the anchored zone", i)
		}
		if key.Protocol != 3 {
			continue
		}
		authenticatedKeys = append(authenticatedKeys, key)
		for _, configuredKey := range configured {
			if sameDNSKEY(key, configuredKey) && !containsDNSKEY(presentAnchors, key) {
				presentAnchors = append(presentAnchors, key)
			}
		}
	}
	if len(presentAnchors) == 0 {
		return nil, errors.New("none of the configured trust anchors are present in the usable DNSKEY RRset")
	}

	if err := VerifyRRset(rrset, signatures, presentAnchors, at); err != nil {
		return nil, fmt.Errorf("DNSKEY RRset signature verification failed: %w", err)
	}
	return authenticatedKeys, nil
}

func sameDNSKEY(a, b *dns.DNSKEY) bool {
	return a != nil && b != nil &&
		strings.EqualFold(dns.Fqdn(a.Hdr.Name), dns.Fqdn(b.Hdr.Name)) &&
		a.Hdr.Class == b.Hdr.Class &&
		a.Flags == b.Flags &&
		a.Protocol == b.Protocol &&
		a.Algorithm == b.Algorithm &&
		a.PublicKey == b.PublicKey
}
