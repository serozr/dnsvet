package dnssec

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// Status describes the outcome of a DNSSEC validation attempt.
// Secure must only be returned after the complete trust chain is validated.
type Status string

const (
	StatusSecure        Status = "secure"
	StatusInsecure      Status = "insecure"
	StatusBogus         Status = "bogus"
	StatusIndeterminate Status = "indeterminate"
)

// Result is a conservative, explainable DNSSEC validation result.
type Result struct {
	Status  Status
	Reason  string
	Zone    string
}

// RRset contains records that share an owner name, class, and type.
// RRSIG records are deliberately kept separate and are not members of an RRset.
type RRset struct {
	Name    string
	Class   uint16
	Type    uint16
	Records []dns.RR
}

type rrsetKey struct {
	name  string
	class uint16
	typ   uint16
}

// GroupRRsets groups ordinary resource records by canonical owner name,
// class, and type. The order of first appearance and the order of records
// within each RRset are preserved. RRSIG records are excluded.
func GroupRRsets(records []dns.RR) ([]RRset, error) {
	groups := make([]RRset, 0)
	indices := make(map[rrsetKey]int)

	for i, record := range records {
		if record == nil {
			return nil, fmt.Errorf("record at index %d is nil", i)
		}

		header := record.Header()
		if header == nil {
			return nil, fmt.Errorf("record at index %d has no DNS header", i)
		}
		if header.Rrtype == dns.TypeRRSIG {
			continue
		}

		name := strings.ToLower(dns.Fqdn(header.Name))
		key := rrsetKey{name: name, class: header.Class, typ: header.Rrtype}
		if index, ok := indices[key]; ok {
			groups[index].Records = append(groups[index].Records, record)
			continue
		}

		indices[key] = len(groups)
		groups = append(groups, RRset{
			Name:    name,
			Class:   header.Class,
			Type:    header.Rrtype,
			Records: []dns.RR{record},
		})
	}

	return groups, nil
}

// SignaturesForRRset returns RRSIG records that cover the supplied RRset.
// Signatures are matched by owner name, class, and covered type.
func SignaturesForRRset(rrset RRset, records []dns.RR) ([]*dns.RRSIG, error) {
	if len(rrset.Records) == 0 {
		return nil, fmt.Errorf("cannot collect signatures for an empty RRset")
	}

	signatures := make([]*dns.RRSIG, 0)
	for i, record := range records {
		if record == nil {
			return nil, fmt.Errorf("record at index %d is nil", i)
		}

		signature, ok := record.(*dns.RRSIG)
		if !ok {
			continue
		}
		if strings.EqualFold(dns.Fqdn(signature.Hdr.Name), rrset.Name) &&
			signature.Hdr.Class == rrset.Class &&
			signature.TypeCovered == rrset.Type {
			signatures = append(signatures, signature)
		}
	}

	return signatures, nil
}
