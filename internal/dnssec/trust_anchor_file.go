package dnssec

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/miekg/dns"
)

const (
	maxTrustAnchorFileSize = 1 << 20
	maxTrustAnchorLineSize = 64 << 10
	maxTrustAnchorKeys     = 32
)

// LoadTrustAnchor reads a bounded DNS master-file fragment containing one or
// more DNSKEY records for exactly one zone. The caller must provision this
// file through a trusted channel; parsing does not establish trust in its
// contents.
func LoadTrustAnchor(reader io.Reader) (TrustAnchor, error) {
	if reader == nil {
		return TrustAnchor{}, fmt.Errorf("trust anchor reader is nil")
	}

	limited := io.LimitReader(reader, maxTrustAnchorFileSize+1)
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 4096), maxTrustAnchorLineSize)

	var anchor TrustAnchor
	seen := make(map[string]struct{})
	total := 0
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		rr, err := dns.NewRR(line)
		if err != nil {
			return TrustAnchor{}, fmt.Errorf("trust anchor line %d: %w", lineNumber, err)
		}
		key, ok := rr.(*dns.DNSKEY)
		if !ok {
			return TrustAnchor{}, fmt.Errorf("trust anchor line %d: expected DNSKEY record", lineNumber)
		}
		if key.Hdr.Class != dns.ClassINET {
			return TrustAnchor{}, fmt.Errorf("trust anchor line %d: only IN class DNSKEY records are supported", lineNumber)
		}
		if key.Protocol != 3 {
			return TrustAnchor{}, fmt.Errorf("trust anchor line %d: DNSKEY protocol must be 3", lineNumber)
		}
		zone := dns.CanonicalName(key.Hdr.Name)
		if anchor.Zone == "" {
			anchor.Zone = zone
		} else if zone != dns.CanonicalName(anchor.Zone) {
			return TrustAnchor{}, fmt.Errorf("trust anchor line %d: multiple zones are not allowed", lineNumber)
		}
		identity := key.String()
		if _, exists := seen[identity]; exists {
			return TrustAnchor{}, fmt.Errorf("trust anchor line %d: duplicate DNSKEY record", lineNumber)
		}
		seen[identity] = struct{}{}
		anchor.DNSKEYs = append(anchor.DNSKEYs, key)
		total++
		if total > maxTrustAnchorKeys {
			return TrustAnchor{}, fmt.Errorf("trust anchor contains more than %d DNSKEY records", maxTrustAnchorKeys)
		}
	}
	if err := scanner.Err(); err != nil {
		return TrustAnchor{}, fmt.Errorf("read trust anchor file: %w", err)
	}
	if anchor.Zone == "" {
		return TrustAnchor{}, fmt.Errorf("trust anchor file contains no DNSKEY records")
	}
	if total == 0 {
		return TrustAnchor{}, fmt.Errorf("trust anchor file contains no DNSKEY records")
	}
	if extra, err := io.ReadAll(limited); err != nil {
		return TrustAnchor{}, fmt.Errorf("read trust anchor file: %w", err)
	} else if len(extra) > 0 {
		return TrustAnchor{}, fmt.Errorf("trust anchor file exceeds %d bytes", maxTrustAnchorFileSize)
	}
	return anchor, nil
}
