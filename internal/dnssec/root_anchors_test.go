package dnssec

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestDefaultRootTrustAnchors(t *testing.T) {
	anchors := DefaultRootTrustAnchors()
	if len(anchors) == 0 {
		t.Fatal("DefaultRootTrustAnchors() returned empty set")
	}

	rootAnchor := anchors[0]
	if rootAnchor.Zone != "." {
		t.Fatalf("expected root anchor zone '.', got %q", rootAnchor.Zone)
	}

	allKeys := rootAnchor.DNSKEYs
	if len(allKeys) < 2 {
		t.Fatalf("expected at least 2 root KSKs (KSK-2017 and KSK-2024), got %d", len(allKeys))
	}

	var found2017, found2024 bool
	for _, key := range allKeys {
		if key == nil {
			t.Fatal("found nil DNSKEY in root trust anchors")
		}
		if key.Protocol != 3 {
			t.Fatalf("key tag %d has protocol %d, want 3", key.KeyTag(), key.Protocol)
		}
		if key.Flags != 257 {
			t.Fatalf("key tag %d has flags %d, want 257 (SEP)", key.KeyTag(), key.Flags)
		}
		if key.Algorithm != dns.RSASHA256 {
			t.Fatalf("key tag %d has algorithm %d, want RSASHA256 (%d)", key.KeyTag(), key.Algorithm, dns.RSASHA256)
		}

		ds := key.ToDS(dns.SHA256)
		if ds == nil {
			t.Fatalf("failed to compute DS for key tag %d", key.KeyTag())
		}

		switch key.KeyTag() {
		case 20326:
			found2017 = true
			expectedDigest := "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
			if !strings.EqualFold(ds.Digest, expectedDigest) {
				t.Errorf("KSK-2017 DS digest = %s, want %s", ds.Digest, expectedDigest)
			}
		case 38696:
			found2024 = true
			expectedDigest := "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"
			if !strings.EqualFold(ds.Digest, expectedDigest) {
				t.Errorf("KSK-2024 DS digest = %s, want %s", ds.Digest, expectedDigest)
			}
		default:
			t.Errorf("unexpected root trust anchor key tag: %d", key.KeyTag())
		}
	}

	if !found2017 {
		t.Error("KSK-2017 (key tag 20326) missing from default root trust anchors")
	}
	if !found2024 {
		t.Error("KSK-2024 (key tag 38696) missing from default root trust anchors")
	}
}
