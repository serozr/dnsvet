package dnssec

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// TrustAnchor is a locally configured DNSKEY trusted independently of DNS.
// The anchor must be provisioned out of band; it is never learned from the
// DNS response being validated.
type TrustAnchor struct {
	Zone   string
	DNSKEY *dns.DNSKEY
}

// ValidateTrustAnchorDNSKEYSet authenticates a zone's DNSKEY RRset using an
// explicitly configured DNSKEY trust anchor. It returns usable zone keys only
// after the DNSKEY RRset signature has been verified by the pinned key.
// DNSKEY records with Protocol values other than 3 remain part of the signed
// RRset, but are not returned as usable keys.
func ValidateTrustAnchorDNSKEYSet(
	rrset RRset,
	signatures []*dns.RRSIG,
	anchor TrustAnchor,
	at time.Time,
) ([]*dns.DNSKEY, error) {
	if anchor.DNSKEY == nil {
		return nil, errors.New("trust anchor DNSKEY is nil")
	}
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
	if !strings.EqualFold(dns.Fqdn(rrset.Name), zone) ||
		!strings.EqualFold(dns.Fqdn(anchor.DNSKEY.Hdr.Name), zone) {
		return nil, errors.New("trust anchor zone does not match DNSKEY RRset")
	}
	if anchor.DNSKEY.Protocol != 3 {
		return nil, fmt.Errorf("invalid trust anchor DNSKEY protocol %d: want 3", anchor.DNSKEY.Protocol)
	}
	if anchor.DNSKEY.Hdr.Rrtype != dns.TypeDNSKEY ||
		anchor.DNSKEY.Hdr.Class != rrset.Class {
		return nil, errors.New("trust anchor DNSKEY metadata does not match the RRset")
	}

	var pinnedKey *dns.DNSKEY
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
		if sameDNSKEY(key, anchor.DNSKEY) {
			pinnedKey = key
		}
	}
	if pinnedKey == nil {
		return nil, errors.New("configured trust anchor is absent from the usable DNSKEY RRset")
	}

	if err := VerifyRRset(rrset, signatures, []*dns.DNSKEY{pinnedKey}, at); err != nil {
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
