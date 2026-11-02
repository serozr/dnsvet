package dnssec

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

type Status string

const (
	StatusSecure        Status = "secure"
	StatusInsecure      Status = "insecure"
	StatusBogus         Status = "bogus"
	StatusIndeterminate Status = "indeterminate"
)

type Result struct {
	Status Status
	Reason string
	Zone   string
}

type RRset struct {
	Name    string
	Class   uint16
	Type    uint16
	Records []dns.RR
}

const (
	// MaxRRsetRecords bounds records accepted for one RRset or grouped input.
	MaxRRsetRecords = 4096
	// MaxRRsetSignatures bounds candidate RRSIG records checked for one RRset.
	MaxRRsetSignatures = 64
	// MaxValidationKeys bounds candidate DNSKEYs checked for one RRset.
	MaxValidationKeys = 256
)

type rrsetKey struct {
	name  string
	class uint16
	typ   uint16
}

func GroupRRsets(records []dns.RR) ([]RRset, error) {
	if len(records) > MaxRRsetRecords {
		return nil, fmt.Errorf("record count %d exceeds maximum %d", len(records), MaxRRsetRecords)
	}

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

func SignaturesForRRset(rrset RRset, records []dns.RR) ([]*dns.RRSIG, error) {
	if len(rrset.Records) == 0 {
		return nil, fmt.Errorf("cannot collect signatures for an empty RRset")
	}
	if len(rrset.Records) > MaxRRsetRecords {
		return nil, fmt.Errorf("RRset record count %d exceeds maximum %d", len(rrset.Records), MaxRRsetRecords)
	}
	if len(records) > MaxRRsetRecords {
		return nil, fmt.Errorf("record count %d exceeds maximum %d", len(records), MaxRRsetRecords)
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
			if len(signatures) > MaxRRsetSignatures {
				return nil, fmt.Errorf("signature count exceeds maximum %d", MaxRRsetSignatures)
			}
		}
	}

	return signatures, nil
}
