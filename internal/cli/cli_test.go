package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestParseBoundedTimeout(t *testing.T) {
	d, err := ParseBoundedTimeout("5s")
	if err != nil || d != 5*time.Second {
		t.Fatalf("ParseBoundedTimeout(5s) = (%v, %v), want (5s, nil)", d, err)
	}

	if _, err := ParseBoundedTimeout("0s"); err == nil {
		t.Fatal("expected error for 0s timeout")
	}
	if _, err := ParseBoundedTimeout("61s"); err == nil {
		t.Fatal("expected error for 61s timeout")
	}
	if _, err := ParseBoundedTimeout("-1s"); err == nil {
		t.Fatal("expected error for negative timeout")
	}
	if _, err := ParseBoundedTimeout("invalid"); err == nil {
		t.Fatal("expected error for unparseable timeout")
	}
}

func TestParseSupportedQType(t *testing.T) {
	qtype, err := ParseSupportedQType("AAAA")
	if err != nil || qtype != dns.TypeAAAA {
		t.Fatalf("ParseSupportedQType(AAAA) = (%d, %v), want (%d, nil)", qtype, err, dns.TypeAAAA)
	}

	if _, err := ParseSupportedQType("UNKNOWN"); err == nil {
		t.Fatal("expected error for unknown record type")
	}
	if _, err := ParseSupportedQType("AXFR"); err == nil {
		t.Fatal("expected error for disallowed type AXFR")
	}
}

func TestParseNormalizedServer(t *testing.T) {
	srv, err := ParseNormalizedServer("8.8.8.8")
	if err != nil || srv != "8.8.8.8:53" {
		t.Fatalf("ParseNormalizedServer(8.8.8.8) = (%q, %v), want 8.8.8.8:53", srv, err)
	}

	if _, err := ParseNormalizedServer("   "); err == nil {
		t.Fatal("expected error for empty server")
	}
}

func TestWriteJSONError(t *testing.T) {
	var buf bytes.Buffer
	WriteJSONError(&buf, "test_code", "test message")
	out := buf.String()
	if !strings.Contains(out, `"schema_version": "1"`) || !strings.Contains(out, "test_code") {
		t.Fatalf("unexpected JSON error output: %s", out)
	}
}
