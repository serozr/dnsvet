package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/serozr/dnsvet/internal/diagnostics"
	"github.com/serozr/dnsvet/internal/discovery"
	"github.com/serozr/dnsvet/internal/dnsclient"
)

type compareJSONEnvelope struct {
	SchemaVersion string                        `json:"schema_version"`
	Comparison    *diagnostics.ComparisonResult `json:"comparison"`
}

// RunCompare executes the compare subcommand.
func RunCompare(args []string, stdout, stderr io.Writer) int {
	jsonRequested := JSONRequestedInArgs(args)
	domain, qtype, resolvers, timeout, strict, jsonOutput, err := ParseCompareOptions(args)
	if err != nil {
		if jsonRequested {
			WriteJSONError(stdout, "invalid_arguments", err.Error())
			return 2
		}
		fmt.Fprintf(stderr, "compare: %v\n", err)
		PrintCompareUsage(stderr)
		return 2
	}

	if len(resolvers) == 0 {
		discovered, err := discovery.DiscoverResolvers()
		if err == nil && len(discovered.Servers) > 0 {
			resolvers = discovered.Servers
		} else {
			resolvers = []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout*2)
	defer cancel()

	client := dnsclient.New(timeout)
	result, err := diagnostics.CompareResolvers(ctx, client, resolvers, domain, qtype, strict)
	if err != nil {
		if jsonOutput {
			WriteJSONError(stdout, "compare_failed", err.Error())
			return 1
		}
		fmt.Fprintf(stderr, "comparison failed: %v\n", err)
		return 1
	}

	if jsonOutput {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(compareJSONEnvelope{
			SchemaVersion: "1",
			Comparison:    result,
		})
	} else {
		fmt.Fprintf(stdout, "Comparing %s (%s) across %d resolvers:\n", domain, dns.TypeToString[qtype], len(resolvers))
		for _, r := range result.Responses {
			if r.Error != "" {
				fmt.Fprintf(stdout, "  [%s]: ERROR (%s)\n", r.Resolver, r.Error)
			} else {
				fmt.Fprintf(stdout, "  [%s]: %s (%.1fms) -> %v\n", r.Resolver, r.Response, r.ElapsedMS, r.Answers)
			}
		}
		switch result.Classification {
		case "consistent":
			fmt.Fprintln(stdout, "\nConsistency: CONSISTENT (all resolvers agree)")
		case "likely_geo_or_load_balanced":
			fmt.Fprintf(stdout, "\nConsistency: LIKELY GEO-DNS / LOAD BALANCED (%s)\n", result.Reason)
		default:
			fmt.Fprintln(stdout, "\nConsistency: INCONSISTENT")
			for _, d := range result.Discrepancies {
				fmt.Fprintf(stdout, "  - %s\n", d)
			}
		}
	}

	if !result.Consistent {
		return 3
	}
	return 0
}

// PrintCompareUsage prints usage for compare.
func PrintCompareUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: dnsvet compare <domain> [--servers <addr1,addr2,...>] [--type <record>] [--timeout <duration>] [--strict] [--json]")
	fmt.Fprintln(w, "Supported types: A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT, CAA, DS, DNSKEY, RRSIG, NSEC, NSEC3")
}

// ParseCompareOptions parses compare command line options.
func ParseCompareOptions(args []string) (string, uint16, []string, time.Duration, bool, bool, error) {
	qtype := dns.TypeA
	timeout := 3 * time.Second
	strict := false
	jsonOutput := false
	var resolvers []string
	var positional []string

	scanner := NewFlagScanner(args)
	for {
		isOption, name, value, hasValue, ok := scanner.Next()
		if !ok {
			break
		}
		if !isOption {
			positional = append(positional, value)
			continue
		}

		switch name {
		case "-h", "--help":
			return "", 0, nil, 0, false, false, fmt.Errorf("help requested")
		case "-t", "--type":
			val, err := scanner.ConsumeValue(name, value, hasValue)
			if err != nil {
				return "", 0, nil, 0, false, false, err
			}
			t, err := ParseSupportedQType(val)
			if err != nil {
				return "", 0, nil, 0, false, false, err
			}
			qtype = t
		case "-s", "--servers", "--server":
			val, err := scanner.ConsumeValue(name, value, hasValue)
			if err != nil {
				return "", 0, nil, 0, false, false, err
			}
			if strings.TrimSpace(val) == "" {
				return "", 0, nil, 0, false, false, fmt.Errorf("resolver address must not be empty")
			}
			for _, s := range strings.Split(val, ",") {
				s = strings.TrimSpace(s)
				if s != "" {
					norm, err := dnsclient.NormalizeServer(s)
					if err != nil {
						return "", 0, nil, 0, false, false, fmt.Errorf("invalid resolver address %q: %w", s, err)
					}
					resolvers = append(resolvers, norm)
				}
			}
			if len(resolvers) == 0 {
				return "", 0, nil, 0, false, false, fmt.Errorf("resolver address must not be empty")
			}
		case "--strict":
			if hasValue {
				return "", 0, nil, 0, false, false, fmt.Errorf("--strict does not accept a value")
			}
			strict = true
		case "--json":
			if hasValue {
				return "", 0, nil, 0, false, false, fmt.Errorf("--json does not accept a value")
			}
			jsonOutput = true
		case "--timeout":
			val, err := scanner.ConsumeValue(name, value, hasValue)
			if err != nil {
				return "", 0, nil, 0, false, false, err
			}
			dur, err := ParseBoundedTimeout(val)
			if err != nil {
				return "", 0, nil, 0, false, false, err
			}
			timeout = dur
		default:
			return "", 0, nil, 0, false, false, fmt.Errorf("unknown option %q", name)
		}
	}

	if len(positional) != 1 {
		return "", 0, nil, 0, false, false, fmt.Errorf("expected exactly one domain name")
	}
	return positional[0], qtype, resolvers, timeout, strict, jsonOutput, nil
}
