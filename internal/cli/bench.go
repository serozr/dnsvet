package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/miekg/dns"
	"github.com/serozr/dnsvet/internal/diagnostics"
	"github.com/serozr/dnsvet/internal/dnsclient"
)

type benchJSONEnvelope struct {
	SchemaVersion string                      `json:"schema_version"`
	Benchmark     *diagnostics.BenchmarkStats `json:"benchmark"`
}

// RunBench executes the bench subcommand.
func RunBench(args []string, stdout, stderr io.Writer) int {
	jsonRequested := JSONRequestedInArgs(args)
	domain, qtype, server, count, timeout, jsonOutput, err := ParseBenchOptions(args)
	if err != nil {
		if jsonRequested {
			WriteJSONError(stdout, "invalid_arguments", err.Error())
			return 2
		}
		fmt.Fprintf(stderr, "bench: %v\n", err)
		PrintBenchUsage(stderr)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout*time.Duration(count+2))
	defer cancel()

	client := dnsclient.New(timeout)
	stats, err := diagnostics.BenchmarkResolver(ctx, client, server, domain, qtype, count)
	if err != nil {
		if jsonOutput {
			WriteJSONError(stdout, "bench_failed", err.Error())
			return 1
		}
		fmt.Fprintf(stderr, "benchmark failed: %v\n", err)
		return 1
	}

	if jsonOutput {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(benchJSONEnvelope{
			SchemaVersion: "1",
			Benchmark:     stats,
		})
		return 0
	}

	fmt.Fprintf(stdout, "Benchmarking %s with %d samples for %s (%s):\n", server, stats.Samples, domain, dns.TypeToString[qtype])
	fmt.Fprintf(stdout, "  Successes: %d/%d (%.1f%% loss)\n", stats.Successes, stats.Samples, stats.LossPercent)
	if stats.Successes > 0 {
		fmt.Fprintf(stdout, "  Min:     %.2f ms\n", stats.MinMS)
		fmt.Fprintf(stdout, "  Median:  %.2f ms\n", stats.MedianMS)
		fmt.Fprintf(stdout, "  P95:     %.2f ms\n", stats.P95MS)
		fmt.Fprintf(stdout, "  Max:     %.2f ms\n", stats.MaxMS)
		fmt.Fprintf(stdout, "  Mean:    %.2f ms ± %.2f ms\n", stats.MeanMS, stats.StdDevMS)
	}
	for _, c := range stats.Caveats {
		fmt.Fprintf(stdout, "  Caveat:  %s\n", c)
	}
	return 0
}

// PrintBenchUsage prints usage for bench.
func PrintBenchUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: dnsvet bench <domain> [--server <address>] [--count <number>] [--type <record>] [--timeout <duration>] [--json]")
	fmt.Fprintln(w, "Supported types: A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT, CAA, DS, DNSKEY, RRSIG, NSEC, NSEC3")
}

// ParseBenchOptions parses bench command line options.
func ParseBenchOptions(args []string) (string, uint16, string, int, time.Duration, bool, error) {
	qtype := dns.TypeA
	server := "1.1.1.1"
	count := 10
	timeout := 3 * time.Second
	jsonOutput := false
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
			return "", 0, "", 0, 0, false, fmt.Errorf("help requested")
		case "-s", "--server":
			val, err := scanner.ConsumeValue(name, value, hasValue)
			if err != nil {
				return "", 0, "", 0, 0, false, err
			}
			norm, err := ParseNormalizedServer(val)
			if err != nil {
				return "", 0, "", 0, 0, false, err
			}
			server = norm
		case "-c", "--count":
			val, err := scanner.ConsumeValue(name, value, hasValue)
			if err != nil {
				return "", 0, "", 0, 0, false, err
			}
			n, err := strconv.Atoi(val)
			if err != nil || n <= 0 || n > 100 {
				return "", 0, "", 0, 0, false, fmt.Errorf("invalid count %q: must be between 1 and 100", val)
			}
			count = n
		case "-t", "--type":
			val, err := scanner.ConsumeValue(name, value, hasValue)
			if err != nil {
				return "", 0, "", 0, 0, false, err
			}
			t, err := ParseSupportedQType(val)
			if err != nil {
				return "", 0, "", 0, 0, false, err
			}
			qtype = t
		case "--json":
			if hasValue {
				return "", 0, "", 0, 0, false, fmt.Errorf("--json does not accept a value")
			}
			jsonOutput = true
		case "--timeout":
			val, err := scanner.ConsumeValue(name, value, hasValue)
			if err != nil {
				return "", 0, "", 0, 0, false, err
			}
			dur, err := ParseBoundedTimeout(val)
			if err != nil {
				return "", 0, "", 0, 0, false, err
			}
			timeout = dur
		default:
			return "", 0, "", 0, 0, false, fmt.Errorf("unknown option %q", name)
		}
	}

	if len(positional) != 1 {
		return "", 0, "", 0, 0, false, fmt.Errorf("expected exactly one domain name")
	}
	return positional[0], qtype, server, count, timeout, jsonOutput, nil
}
