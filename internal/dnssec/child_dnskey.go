package dnssec

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var ErrNoDSMatchedDNSKEY = errors.New("DNSKEY RRset does not contain a DS-authenticated key")

// ValidateChildDNSKEYSet verifies a child zone's DNSKEY RRset using only keys
// authenticated by its parent's DS RRset. It returns the complete child key
// set only after the RRset signature has been successfully verified.
func ValidateChildDNSKEYSet(
	childZone string,
	rrset RRset,
	signatures []*dns.RRSIG,
	dsMatchedKeys []*dns.DNSKEY,
	at time.Time,
) ([]*dns.DNSKEY, error) {
	if childZone == "" {
		return nil, errors.New("child zone is empty")
	}
	if len(rrset.Records) == 0 {
		return nil, errors.New("child DNSKEY RRset is empty")
	}
	if rrset.Type != dns.TypeDNSKEY {
		return nil, fmt.Errorf("child key validation requires a DNSKEY RRset, got type %d", rrset.Type)
	}
	if len(dsMatchedKeys) == 0 {
		return nil, errors.New("DS-authenticated child DNSKEYs are required")
	}

	zone := dns.Fqdn(childZone)
	if !strings.EqualFold(dns.Fqdn(rrset.Name), zone) {
		return nil, errors.New("child zone does not match DNSKEY RRset owner")
	}

	keys := make([]*dns.DNSKEY, 0, len(rrset.Records))
	for i, record := range rrset.Records {
		key, ok := record.(*dns.DNSKEY)
		if !ok {
			return nil, fmt.Errorf("child DNSKEY RRset record at index %d is not a DNSKEY", i)
		}
		if key.Protocol != 3 {
			return nil, fmt.Errorf("child DNSKEY at index %d has invalid protocol %d", i, key.Protocol)
		}
		if key.Hdr.Class != rrset.Class ||
			!strings.EqualFold(dns.Fqdn(key.Hdr.Name), zone) {
			return nil, fmt.Errorf("child DNSKEY at index %d does not belong to zone %q", i, zone)
		}
		keys = append(keys, key)
	}

	authenticatedSigners := make([]*dns.DNSKEY, 0, len(dsMatchedKeys))
	for i, key := range dsMatchedKeys {
		if key == nil {
			return nil, fmt.Errorf("DS-matched DNSKEY at index %d is nil", i)
		}
		if key.Protocol != 3 || key.Hdr.Class != rrset.Class ||
			!strings.EqualFold(dns.Fqdn(key.Hdr.Name), zone) {
			return nil, fmt.Errorf("DS-matched DNSKEY at index %d does not belong to child zone %q", i, zone)
		}
		for _, rrsetKey := range keys {
			if sameDNSKEY(rrsetKey, key) {
				if !containsDNSKEY(authenticatedSigners, rrsetKey) {
					authenticatedSigners = append(authenticatedSigners, rrsetKey)
				}
				break
			}
		}
	}
	if len(authenticatedSigners) == 0 {
		return nil, ErrNoDSMatchedDNSKEY
	}

	if err := VerifyRRset(rrset, signatures, authenticatedSigners, at); err != nil {
		return nil, fmt.Errorf("child DNSKEY RRset signature verification failed: %w", err)
	}
	return keys, nil
}
