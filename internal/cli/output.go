package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/miekg/dns"
)

type jsonEnvelopeError struct {
	SchemaVersion string          `json:"schema_version"`
	Error         jsonErrorDetail `json:"error"`
}

type jsonErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// WriteJSONError writes a standard schema_version 1 error JSON response.
func WriteJSONError(w io.Writer, code, message string) {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(jsonEnvelopeError{
		SchemaVersion: "1",
		Error:         jsonErrorDetail{Code: code, Message: message},
	})
}

// LocalValidationStatus returns metadata indicator for query JSON output.
func LocalValidationStatus(dnssecRequested bool) string {
	if !dnssecRequested {
		return ""
	}
	return "not_performed"
}

// FormatAnswer produces consistent presentation text for a DNS record.
func FormatAnswer(record dns.RR) string {
	header := record.Header()
	prefix := fmt.Sprintf("%s %d IN %s", header.Name, header.Ttl, dns.TypeToString[header.Rrtype])

	switch rr := record.(type) {
	case *dns.A:
		return fmt.Sprintf("%s %s", prefix, rr.A)
	case *dns.AAAA:
		return fmt.Sprintf("%s %s", prefix, rr.AAAA)
	case *dns.CNAME:
		return fmt.Sprintf("%s %s", prefix, rr.Target)
	case *dns.NS:
		return fmt.Sprintf("%s %s", prefix, rr.Ns)
	case *dns.PTR:
		return fmt.Sprintf("%s %s", prefix, rr.Ptr)
	case *dns.MX:
		return fmt.Sprintf("%s %d %s", prefix, rr.Preference, rr.Mx)
	case *dns.TXT:
		return fmt.Sprintf("%s %s", prefix, strings.Join(rr.Txt, " "))
	case *dns.SRV:
		return fmt.Sprintf("%s %d %d %d %s", prefix, rr.Priority, rr.Weight, rr.Port, rr.Target)
	case *dns.SOA:
		return fmt.Sprintf("%s mname=%s rname=%s serial=%d refresh=%d retry=%d expire=%d minttl=%d",
			prefix, rr.Ns, rr.Mbox, rr.Serial, rr.Refresh, rr.Retry, rr.Expire, rr.Minttl)
	case *dns.CAA:
		return fmt.Sprintf("%s %d %s %q", prefix, rr.Flag, rr.Tag, rr.Value)
	default:
		return record.String()
	}
}
