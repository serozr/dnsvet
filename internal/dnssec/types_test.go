package dnssec

import (
	"testing"

	"github.com/miekg/dns"
)

func mustRR(t *testing.T, value string) dns.RR {
	t.Helper()
	record, err := dns.NewRR(value)
	if err != nil {
		t.Fatalf("dns.NewRR(%q): %v", value, err)
	}
	return record
}

func TestGroupRRsetsGroupsByOwnerClassAndType(t *testing.T) {
	records := []dns.RR{
		mustRR(t, "example.test. 60 IN A 192.0.2.1"),
		mustRR(t, "www.example.test. 60 IN A 192.0.2.2"),
		mustRR(t, "example.test. 60 IN AAAA 2001:db8::1"),
		mustRR(t, "EXAMPLE.TEST. 30 IN A 192.0.2.3"),
		mustRR(t, "example.test. 60 CH A 192.0.2.4"),
		mustRR(t, "example.test. 60 IN RRSIG A 8 2 60 20300101000000 20200101000000 12345 example.test. AA=="),
	}

	groups, err := GroupRRsets(records)
	if err != nil {
		t.Fatalf("GroupRRsets() error = %v", err)
	}
	if len(groups) != 4 {
		t.Fatalf("GroupRRsets() returned %d groups, want 4", len(groups))
	}

	if groups[0].Name != "example.test." || groups[0].Class != dns.ClassINET || groups[0].Type != dns.TypeA {
		t.Fatalf("first RRset key = %#v, unexpected", groups[0])
	}
	if len(groups[0].Records) != 2 {
		t.Fatalf("first RRset has %d records, want 2", len(groups[0].Records))
	}
	if groups[1].Type != dns.TypeA || groups[1].Name != "www.example.test." {
		t.Fatalf("second RRset = %#v, unexpected", groups[1])
	}
	if groups[2].Type != dns.TypeAAAA {
		t.Fatalf("third RRset type = %d, want AAAA", groups[2].Type)
	}
	if groups[3].Class != dns.ClassCHAOS {
		t.Fatalf("fourth RRset class = %d, want CHAOS", groups[3].Class)
	}
}

func TestGroupRRsetsRejectsNilRecord(t *testing.T) {
	if _, err := GroupRRsets([]dns.RR{nil}); err == nil {
		t.Fatal("GroupRRsets() error = nil, want error")
	}
}

func TestGroupRRsetsEmptyInput(t *testing.T) {
	groups, err := GroupRRsets(nil)
	if err != nil {
		t.Fatalf("GroupRRsets() error = %v", err)
	}
	if len(groups) != 0 {
		t.Fatalf("GroupRRsets() returned %d groups, want 0", len(groups))
	}
}

func TestSignaturesForRRsetMatchesOwnerClassAndCoveredType(t *testing.T) {
	groups, err := GroupRRsets([]dns.RR{
		mustRR(t, "example.test. 60 IN A 192.0.2.1"),
	})
	if err != nil {
		t.Fatalf("GroupRRsets() error = %v", err)
	}

	records := []dns.RR{
		mustRR(t, "example.test. 60 IN RRSIG A 8 2 60 20300101000000 20200101000000 12345 example.test. AA=="),
		mustRR(t, "other.test. 60 IN RRSIG A 8 2 60 20300101000000 20200101000000 12345 example.test. AA=="),
		mustRR(t, "example.test. 60 IN RRSIG AAAA 8 2 60 20300101000000 20200101000000 12345 example.test. AA=="),
		mustRR(t, "example.test. 60 CH RRSIG A 8 2 60 20300101000000 20200101000000 12345 example.test. AA=="),
	}

	signatures, err := SignaturesForRRset(groups[0], records)
	if err != nil {
		t.Fatalf("SignaturesForRRset() error = %v", err)
	}
	if len(signatures) != 1 {
		t.Fatalf("SignaturesForRRset() returned %d signatures, want 1", len(signatures))
	}
}

func TestSignaturesForRRsetRejectsEmptyRRset(t *testing.T) {
	_, err := SignaturesForRRset(RRset{}, nil)
	if err == nil {
		t.Fatal("SignaturesForRRset() error = nil, want error")
	}
}

func TestGroupRRsetsRejectsExcessiveInput(t *testing.T) {
	records := make([]dns.RR, MaxRRsetRecords+1)
	if _, err := GroupRRsets(records); err == nil {
		t.Fatal("GroupRRsets() error = nil, want record limit error")
	}
}
