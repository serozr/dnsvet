package dnssec

import (
	"errors"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func mustDNSKEY(t *testing.T) *dns.DNSKEY {
	t.Helper()
	record, err := dns.NewRR("example.test. 3600 IN DNSKEY 257 3 8 AQIDBAUGBwg=")
	if err != nil {
		t.Fatalf("dns.NewRR(DNSKEY): %v", err)
	}
	key, ok := record.(*dns.DNSKEY)
	if !ok {
		t.Fatal("parsed record is not a DNSKEY")
	}
	return key
}

func TestMatchDNSKEYToDS(t *testing.T) {
	key := mustDNSKEY(t)
	ds := key.ToDS(dns.SHA256)

	matched, err := MatchDNSKEYToDS(key, ds)
	if err != nil {
		t.Fatalf("MatchDNSKEYToDS() error = %v", err)
	}
	if !matched {
		t.Fatal("MatchDNSKEYToDS() = false, want true")
	}

	ds.Digest = strings.ToLower(ds.Digest)
	matched, err = MatchDNSKEYToDS(key, ds)
	if err != nil || !matched {
		t.Fatalf("case-insensitive digest match = %v, error = %v", matched, err)
	}
}

func TestMatchDNSKEYToDSRejectsMismatches(t *testing.T) {
	key := mustDNSKEY(t)
	base := key.ToDS(dns.SHA256)

	tests := []struct {
		name   string
		mutate func(*dns.DS)
	}{
		{name: "owner", mutate: func(ds *dns.DS) { ds.Hdr.Name = "other.test." }},
		{name: "class", mutate: func(ds *dns.DS) { ds.Hdr.Class = dns.ClassCHAOS }},
		{name: "key tag", mutate: func(ds *dns.DS) { ds.KeyTag++ }},
		{name: "algorithm", mutate: func(ds *dns.DS) { ds.Algorithm++ }},
		{name: "digest type", mutate: func(ds *dns.DS) { ds.DigestType = dns.SHA384 }},
		{name: "digest", mutate: func(ds *dns.DS) { ds.Digest = strings.Repeat("0", len(ds.Digest)) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds := *base
			tt.mutate(&ds)
			matched, err := MatchDNSKEYToDS(key, &ds)
			if err != nil {
				t.Fatalf("MatchDNSKEYToDS() error = %v", err)
			}
			if matched {
				t.Fatal("MatchDNSKEYToDS() = true, want false")
			}
		})
	}
}

func TestMatchDNSKEYToDSRejectsUnsupportedDigest(t *testing.T) {
	key := mustDNSKEY(t)
	ds := &dns.DS{
		Hdr:        dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeDS, Class: dns.ClassINET},
		DigestType: 250,
	}
	_, err := MatchDNSKEYToDS(key, ds)
	if !errors.Is(err, ErrUnsupportedDigest) {
		t.Fatalf("error = %v, want ErrUnsupportedDigest", err)
	}
}

func TestMatchDNSKEYToDSRejectsInvalidProtocol(t *testing.T) {
	key := mustDNSKEY(t)
	key.Protocol = 2
	ds := key.ToDS(dns.SHA256)
	_, err := MatchDNSKEYToDS(key, ds)
	if err == nil {
		t.Fatal("MatchDNSKEYToDS() error = nil, want invalid protocol error")
	}
}

func TestMatchDNSKEYToDSRejectsNilInputs(t *testing.T) {
	key := mustDNSKEY(t)
	ds := key.ToDS(dns.SHA256)

	if _, err := MatchDNSKEYToDS(nil, ds); err == nil {
		t.Fatal("nil DNSKEY should return an error")
	}
	if _, err := MatchDNSKEYToDS(key, nil); err == nil {
		t.Fatal("nil DS should return an error")
	}
}

func TestMatchDNSKEYToDSRejectsWrongRecordTypes(t *testing.T) {
	key := mustDNSKEY(t)
	ds := key.ToDS(dns.SHA256)
	wrongKey := *key
	wrongKey.Hdr.Rrtype = dns.TypeA
	if _, err := MatchDNSKEYToDS(&wrongKey, ds); err == nil {
		t.Fatal("MatchDNSKEYToDS() error = nil, want DNSKEY type error")
	}

	wrongDS := *ds
	wrongDS.Hdr.Rrtype = dns.TypeA
	if _, err := MatchDNSKEYToDS(key, &wrongDS); err == nil {
		t.Fatal("MatchDNSKEYToDS() error = nil, want DS type error")
	}
}
