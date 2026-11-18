package diagnostics

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/serozr/dnsvet/internal/dnsclient"
)

// ResolverResponse records one resolver's answer and metrics.
type ResolverResponse struct {
	Resolver  string   `json:"resolver"`
	RCode     int      `json:"rcode"`
	Response  string   `json:"response"`
	Answers   []string `json:"answers"`
	ElapsedMS float64  `json:"elapsed_ms"`
	Error     string   `json:"error,omitempty"`
}

// ComparisonResult summarizes the consistency across all queried resolvers.
type ComparisonResult struct {
	Domain         string             `json:"domain"`
	Type           string             `json:"type"`
	Consistent     bool               `json:"consistent"`
	Classification string             `json:"classification"` // "consistent", "inconsistent", "likely_geo_or_load_balanced"
	Reason         string             `json:"reason,omitempty"`
	Strict         bool               `json:"strict,omitempty"`
	Discrepancies  []string           `json:"discrepancies,omitempty"`
	Responses      []ResolverResponse `json:"responses"`
}

// CompareResolvers queries multiple resolvers for domain and qtype under controlled conditions,
// performing order-insensitive answer comparisons and rcode checks.
func CompareResolvers(
	ctx context.Context,
	client *dnsclient.Client,
	resolvers []string,
	domain string,
	qtype uint16,
	strict bool,
) (*ComparisonResult, error) {
	if len(resolvers) == 0 {
		return nil, fmt.Errorf("at least one resolver is required for comparison")
	}
	if client == nil {
		client = dnsclient.New(3 * time.Second)
	}

	result := &ComparisonResult{
		Domain:    domain,
		Type:      dns.TypeToString[qtype],
		Strict:    strict,
		Responses: make([]ResolverResponse, len(resolvers)),
	}

	var wg sync.WaitGroup
	// Bounded concurrency (max 4 concurrent queries)
	sem := make(chan struct{}, 4)

	for i, resolver := range resolvers {
		wg.Add(1)
		go func(idx int, srv string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			resp, elapsed, err := client.Query(ctx, srv, domain, qtype)
			rr := ResolverResponse{
				Resolver:  srv,
				ElapsedMS: float64(elapsed) / float64(time.Millisecond),
			}
			if err != nil {
				rr.Error = err.Error()
			} else if resp != nil {
				rr.RCode = resp.Rcode
				rr.Response = dns.RcodeToString[resp.Rcode]
				if rr.Response == "" {
					rr.Response = fmt.Sprintf("RCODE_%d", resp.Rcode)
				}
				rr.Answers = make([]string, 0, len(resp.Answer))
				for _, ans := range resp.Answer {
					rr.Answers = append(rr.Answers, formatAnswerString(ans))
				}
				sort.Strings(rr.Answers)
			}
			result.Responses[idx] = rr
		}(i, resolver)
	}

	wg.Wait()

	// Analyze discrepancies
	result.Consistent = true
	var baseAnswers []string
	baseRcode := -1
	firstSuccess := false
	allNoerrorWithAnswers := true
	answerSetsDiffer := false

	for _, r := range result.Responses {
		if r.Error != "" {
			result.Consistent = false
			allNoerrorWithAnswers = false
			result.Discrepancies = append(result.Discrepancies, fmt.Sprintf("resolver %s failed: %s", r.Resolver, r.Error))
			continue
		}
		if r.RCode != dns.RcodeSuccess || len(r.Answers) == 0 {
			allNoerrorWithAnswers = false
		}
		if !firstSuccess {
			firstSuccess = true
			baseRcode = r.RCode
			baseAnswers = r.Answers
			continue
		}
		if r.RCode != baseRcode {
			result.Consistent = false
			result.Discrepancies = append(result.Discrepancies, fmt.Sprintf("response code mismatch: %s returned %s (%d), baseline was %s (%d)",
				r.Resolver, r.Response, r.RCode, dns.RcodeToString[baseRcode], baseRcode))
		}
		if !equalStringSlices(r.Answers, baseAnswers) {
			answerSetsDiffer = true
			result.Discrepancies = append(result.Discrepancies, fmt.Sprintf("answer mismatch between %s and baseline: got %v, want %v",
				r.Resolver, r.Answers, baseAnswers))
		}
	}

	if len(result.Discrepancies) == 0 {
		result.Classification = "consistent"
		result.Consistent = true
		result.Reason = "all resolvers returned identical answers"
		return result, nil
	}

	// If the only differences are answer IPs for A/AAAA and all resolvers answered NOERROR:
	isAddressQuery := qtype == dns.TypeA || qtype == dns.TypeAAAA
	if allNoerrorWithAnswers && isAddressQuery && answerSetsDiffer && len(result.Discrepancies) > 0 {
		// Check that there were no RCODE mismatches or query failures
		allRcodesMatch := true
		for _, r := range result.Responses {
			if r.RCode != dns.RcodeSuccess || r.Error != "" {
				allRcodesMatch = false
				break
			}
		}

		if allRcodesMatch {
			if strict {
				result.Classification = "inconsistent"
				result.Consistent = false
				result.Reason = "differing IP answers observed and --strict comparison was requested"
			} else {
				result.Classification = "likely_geo_or_load_balanced"
				result.Consistent = true
				result.Reason = "all resolvers returned successful answers with differing IP sets, typical for CDN or GeoDNS routing"
			}
			return result, nil
		}
	}

	result.Classification = "inconsistent"
	result.Consistent = false
	result.Reason = "discrepancies detected across resolver answers"
	return result, nil
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !strings.EqualFold(a[i], b[i]) {
			return false
		}
	}
	return true
}

func formatAnswerString(rr dns.RR) string {
	hdr := rr.Header()
	switch record := rr.(type) {
	case *dns.A:
		return fmt.Sprintf("A %s", record.A)
	case *dns.AAAA:
		return fmt.Sprintf("AAAA %s", record.AAAA)
	case *dns.CNAME:
		return fmt.Sprintf("CNAME %s", record.Target)
	case *dns.TXT:
		return fmt.Sprintf("TXT %s", strings.Join(record.Txt, " "))
	default:
		return fmt.Sprintf("%s %s", dns.TypeToString[hdr.Rrtype], rr.String())
	}
}
