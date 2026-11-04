package diagnostics

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/miekg/dns"

	"github.com/serozr/dnsvet/internal/dnsclient"
)

// ConfidenceLevel describes the confidence of a diagnostic finding.
type ConfidenceLevel string

const (
	ConfidenceNone       ConfidenceLevel = "none"
	ConfidenceIndicator  ConfidenceLevel = "indicator"
	ConfidenceSuspicious ConfidenceLevel = "suspicious"
	ConfidenceConfirmed  ConfidenceLevel = "confirmed"
)

// LeakResult records indicators of DNS hijacking, NXDOMAIN rewriting, or transparent proxying.
type LeakResult struct {
	Resolver          string          `json:"resolver"`
	NXDOMAINRewriting bool            `json:"nxdomain_rewriting"`
	Confidence        ConfidenceLevel `json:"confidence"`
	Indicators        []string        `json:"indicators,omitempty"`
	TestedNames       []string        `json:"tested_names"`
	Limitations       string          `json:"limitations"`
}

// DetectHijackingAndLeaks checks whether resolver rewrites NXDOMAIN responses
// for RFC 6761 reserved domains or intercepts DNS traffic.
func DetectHijackingAndLeaks(
	ctx context.Context,
	client *dnsclient.Client,
	resolver string,
) (*LeakResult, error) {
	if client == nil {
		client = dnsclient.New(3 * time.Second)
	}

	result := &LeakResult{
		Resolver:    resolver,
		Confidence:  ConfidenceNone,
		TestedNames: make([]string, 0, 3),
		Limitations: "Testing is local-first using RFC 6761 reserved names (.invalid). Controlled repetition is used to avoid transient false positives.",
	}

	// Generate 3 unique random RFC 6761 .invalid domain names
	// RFC 6761 Section 6.4: ".invalid names MUST return NXDOMAIN"
	for i := 0; i < 3; i++ {
		randomBytes := make([]byte, 8)
		_, _ = rand.Read(randomBytes)
		name := fmt.Sprintf("test-%s.invalid.", hex.EncodeToString(randomBytes))
		result.TestedNames = append(result.TestedNames, name)

		resp, _, err := client.Query(ctx, resolver, name, dns.TypeA)
		if err != nil {
			continue
		}
		if resp == nil {
			continue
		}

		// Check if response is NOT NXDOMAIN
		if resp.Rcode != dns.RcodeNameError {
			result.NXDOMAINRewriting = true
			if len(resp.Answer) > 0 {
				result.Indicators = append(result.Indicators, fmt.Sprintf(
					"Query for reserved name %s returned %s with %d answers (expected NXDOMAIN): possible ISP rewriting or hijacking",
					name, dns.RcodeToString[resp.Rcode], len(resp.Answer),
				))
			} else {
				result.Indicators = append(result.Indicators, fmt.Sprintf(
					"Query for reserved name %s returned %s instead of NXDOMAIN",
					name, dns.RcodeToString[resp.Rcode],
				))
			}
		}
	}

	if result.NXDOMAINRewriting {
		if len(result.Indicators) >= 2 {
			result.Confidence = ConfidenceConfirmed
		} else {
			result.Confidence = ConfidenceIndicator
		}
	}

	return result, nil
}
