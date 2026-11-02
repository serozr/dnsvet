package dnssec

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

var ErrUnsupportedDigest = errors.New("unsupported DS digest type")

// MatchDNSKEYToDS reports whether key matches ds using the DS digest.
// SHA-1 is accepted for legacy interoperability, but SHA-256 or SHA-384
// should be preferred when creating new DS records.
func MatchDNSKEYToDS(key *dns.DNSKEY, ds *dns.DS) (bool, error) {
	if key == nil {
		return false, errors.New("DNSKEY is nil")
	}
	if ds == nil {
		return false, errors.New("DS is nil")
	}
	if key.Hdr.Rrtype != dns.TypeDNSKEY {
		return false, fmt.Errorf("record type %d is not DNSKEY", key.Hdr.Rrtype)
	}
	if ds.Hdr.Rrtype != dns.TypeDS {
		return false, fmt.Errorf("record type %d is not DS", ds.Hdr.Rrtype)
	}
	if key.Hdr.Name == "" || ds.Hdr.Name == "" {
		return false, errors.New("DNSKEY and DS owner names must not be empty")
	}
	if key.Hdr.Class == 0 || ds.Hdr.Class == 0 {
		return false, errors.New("DNSKEY and DS classes must not be zero")
	}
	if key.Protocol != 3 {
		return false, fmt.Errorf("invalid DNSKEY protocol %d: want 3", key.Protocol)
	}
	if !strings.EqualFold(dns.Fqdn(key.Hdr.Name), dns.Fqdn(ds.Hdr.Name)) {
		return false, nil
	}
	if key.Hdr.Class != ds.Hdr.Class {
		return false, nil
	}

	expected := key.ToDS(ds.DigestType)
	if expected == nil {
		return false, fmt.Errorf("%w: %d", ErrUnsupportedDigest, ds.DigestType)
	}

	return expected.KeyTag == ds.KeyTag &&
		expected.Algorithm == ds.Algorithm &&
		expected.DigestType == ds.DigestType &&
		strings.EqualFold(expected.Digest, ds.Digest), nil
}
