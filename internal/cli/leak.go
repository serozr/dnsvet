package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/serozr/dnsvet/internal/diagnostics"
	"github.com/serozr/dnsvet/internal/dnsclient"
)

type leakJSONEnvelope struct {
	SchemaVersion string                  `json:"schema_version"`
	LeakReport    *diagnostics.LeakResult `json:"leak_report"`
}

// RunLeak executes the leak / hijack subcommand.
func RunLeak(args []string, stdout, stderr io.Writer) int {
	jsonRequested := JSONRequestedInArgs(args)
	server, timeout, jsonOutput, err := ParseLeakOptions(args)
	if err != nil {
		if jsonRequested {
			WriteJSONError(stdout, "invalid_arguments", err.Error())
			return 2
		}
		fmt.Fprintf(stderr, "leak: %v\n", err)
		PrintLeakUsage(stderr)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout*5)
	defer cancel()

	client := dnsclient.New(timeout)
	result, err := diagnostics.DetectHijackingAndLeaks(ctx, client, server)
	if err != nil {
		if jsonOutput {
			WriteJSONError(stdout, "leak_check_failed", err.Error())
			return 1
		}
		fmt.Fprintf(stderr, "leak check failed: %v\n", err)
		return 1
	}

	if jsonOutput {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(leakJSONEnvelope{
			SchemaVersion: "1",
			LeakReport:    result,
		})
	} else {
		fmt.Fprintf(stdout, "Testing %s for DNS hijacking & NXDOMAIN rewriting:\n", server)
		if result.NXDOMAINRewriting {
			fmt.Fprintf(stdout, "  Result: HIJACKING / REWRITING DETECTED\n")
			fmt.Fprintf(stdout, "  Confidence: %s\n", result.Confidence)
			for _, ind := range result.Indicators {
				fmt.Fprintf(stdout, "  Indicator: %s\n", ind)
			}
		} else {
			fmt.Fprintf(stdout, "  Result: NO REWRITING DETECTED (compliant NXDOMAIN responses for RFC 6761 names)\n")
			fmt.Fprintf(stdout, "  Confidence: %s\n", result.Confidence)
		}
		fmt.Fprintf(stdout, "  Tested Names: %v\n", result.TestedNames)
		fmt.Fprintf(stdout, "  Limitations: %s\n", result.Limitations)
	}

	if result.NXDOMAINRewriting {
		return 3
	}
	return 0
}

// PrintLeakUsage prints usage for leak.
func PrintLeakUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: dnsvet leak [--server <address>] [--timeout <duration>] [--json]")
}

// ParseLeakOptions parses leak command line options.
func ParseLeakOptions(args []string) (string, time.Duration, bool, error) {
	server := "1.1.1.1"
	timeout := 3 * time.Second
	jsonOutput := false

	scanner := NewFlagScanner(args)
	for {
		isOption, name, value, hasValue, ok := scanner.Next()
		if !ok {
			break
		}
		if !isOption {
			return "", 0, false, fmt.Errorf("unexpected argument %q", value)
		}

		switch name {
		case "-h", "--help":
			return "", 0, false, fmt.Errorf("help requested")
		case "-s", "--server":
			val, err := scanner.ConsumeValue(name, value, hasValue)
			if err != nil {
				return "", 0, false, err
			}
			norm, err := ParseNormalizedServer(val)
			if err != nil {
				return "", 0, false, err
			}
			server = norm
		case "--json":
			if hasValue {
				return "", 0, false, fmt.Errorf("--json does not accept a value")
			}
			jsonOutput = true
		case "--timeout":
			val, err := scanner.ConsumeValue(name, value, hasValue)
			if err != nil {
				return "", 0, false, err
			}
			dur, err := ParseBoundedTimeout(val)
			if err != nil {
				return "", 0, false, err
			}
			timeout = dur
		default:
			return "", 0, false, fmt.Errorf("unknown option %q", name)
		}
	}
	return server, timeout, jsonOutput, nil
}
