package dnssec

import (
	"bufio"
	"bytes"
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
// more DNSKEY records for exactly one zone. Parenthesized multiline records
// and comments are supported. The caller must provision this file through a
// trusted channel; parsing does not establish trust in its contents.
func LoadTrustAnchor(reader io.Reader) (TrustAnchor, error) {
	if reader == nil {
		return TrustAnchor{}, fmt.Errorf("trust anchor reader is nil")
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxTrustAnchorFileSize+1))
	if err != nil {
		return TrustAnchor{}, fmt.Errorf("read trust anchor file: %w", err)
	}
	if len(data) > maxTrustAnchorFileSize {
		return TrustAnchor{}, fmt.Errorf("trust anchor file exceeds %d bytes", maxTrustAnchorFileSize)
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxTrustAnchorLineSize)
	var anchor TrustAnchor
	seen := make(map[string]struct{})
	var record strings.Builder
	recordStart, lineNumber, depth := 0, 0, 0
	quoted, escaped := false, false

	parseRecord := func(text string, startLine int) error {
		if strings.TrimSpace(text) == "" {
			return nil
		}
		rr, err := dns.NewRR(text)
		if err != nil {
			return fmt.Errorf("trust anchor line %d: %w", startLine, err)
		}
		key, ok := rr.(*dns.DNSKEY)
		if !ok {
			return fmt.Errorf("trust anchor line %d: expected DNSKEY record", startLine)
		}
		if key.Hdr.Class != dns.ClassINET {
			return fmt.Errorf("trust anchor line %d: only IN class DNSKEY records are supported", startLine)
		}
		if key.Protocol != 3 {
			return fmt.Errorf("trust anchor line %d: DNSKEY protocol must be 3", startLine)
		}
		if key.Flags&0x0100 == 0 {
			return fmt.Errorf("trust anchor line %d: DNSKEY Zone flag must be set", startLine)
		}
		zone := dns.CanonicalName(key.Hdr.Name)
		if anchor.Zone == "" {
			anchor.Zone = zone
		} else if zone != dns.CanonicalName(anchor.Zone) {
			return fmt.Errorf("trust anchor line %d: multiple zones are not allowed", startLine)
		}
		identity := key.String()
		if _, exists := seen[identity]; exists {
			return fmt.Errorf("trust anchor line %d: duplicate DNSKEY record", startLine)
		}
		seen[identity] = struct{}{}
		anchor.DNSKEYs = append(anchor.DNSKEYs, key)
		if len(anchor.DNSKEYs) > maxTrustAnchorKeys {
			return fmt.Errorf("trust anchor contains more than %d DNSKEY records", maxTrustAnchorKeys)
		}
		return nil
	}

	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if record.Len() == 0 && (trimmed == "" || strings.HasPrefix(trimmed, ";")) {
			continue
		}
		if record.Len() == 0 {
			recordStart = lineNumber
		}
		record.WriteString(line)
		record.WriteByte('\n')

		for i := 0; i < len(line); i++ {
			ch := line[i]
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '"' {
				quoted = !quoted
				continue
			}
			if quoted {
				continue
			}
			if ch == ';' {
				break
			}
			switch ch {
			case '(':
				depth++
			case ')':
				depth--
				if depth < 0 {
					return TrustAnchor{}, fmt.Errorf("trust anchor line %d: unmatched closing parenthesis", lineNumber)
				}
			}
		}
		if depth == 0 {
			if err := parseRecord(record.String(), recordStart); err != nil {
				return TrustAnchor{}, err
			}
			record.Reset()
			quoted, escaped = false, false
		}
	}
	if err := scanner.Err(); err != nil {
		return TrustAnchor{}, fmt.Errorf("read trust anchor file: %w", err)
	}
	if depth != 0 || quoted {
		return TrustAnchor{}, fmt.Errorf("trust anchor line %d: unterminated multiline DNSKEY record", recordStart)
	}
	if record.Len() > 0 {
		if err := parseRecord(record.String(), recordStart); err != nil {
			return TrustAnchor{}, err
		}
	}
	if len(anchor.DNSKEYs) == 0 {
		return TrustAnchor{}, fmt.Errorf("trust anchor file contains no DNSKEY records")
	}
	return anchor, nil
}
