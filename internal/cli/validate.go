package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/serozr/dnsvet/internal/dnsclient"
	"github.com/serozr/dnsvet/internal/dnssec"
)

type validateJSONOutput struct {
	SchemaVersion string   `json:"schema_version"`
	Domain        string   `json:"domain"`
	Type          string   `json:"type"`
	Status        string   `json:"status"`
	Reason        string   `json:"reason"`
	Zone          string   `json:"zone"`
	TrustAnchor   string   `json:"trust_anchor"`
	ProofType     string   `json:"proof_type,omitempty"`
	Wildcard      bool     `json:"wildcard"`
	Elapsed       string   `json:"elapsed"`
	ElapsedMS     float64  `json:"elapsed_ms"`
	Answers       []string `json:"answers,omitempty"`
}

// RunValidate executes the validate subcommand.
func RunValidate(args []string, stdout, stderr io.Writer) int {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			PrintValidateUsage(stdout)
			return 0
		}
	}

	jsonRequested := JSONRequestedInArgs(args)
	options, anchorPath, err := ParseValidateOptions(args)
	if err != nil {
		if jsonRequested {
			WriteJSONError(stdout, "invalid_arguments", err.Error())
			return 2
		}
		fmt.Fprintf(stderr, "validate: %v\n", err)
		PrintValidateUsage(stderr)
		return 2
	}

	var anchors []dnssec.TrustAnchor
	if anchorPath != "" {
		f, err := os.Open(anchorPath)
		if err != nil {
			if jsonRequested {
				WriteJSONError(stdout, "invalid_trust_anchor", err.Error())
				return 2
			}
			fmt.Fprintf(stderr, "failed to open trust anchor file %s: %v\n", anchorPath, err)
			return 2
		}
		defer f.Close()
		loaded, err := dnssec.LoadTrustAnchor(f)
		if err != nil {
			if jsonRequested {
				WriteJSONError(stdout, "invalid_trust_anchor", err.Error())
				return 2
			}
			fmt.Fprintf(stderr, "failed to load trust anchor from %s: %v\n", anchorPath, err)
			return 2
		}
		anchors = []dnssec.TrustAnchor{loaded}
	} else {
		anchors = dnssec.DefaultRootTrustAnchors()
	}

	ctx, cancel := context.WithTimeout(context.Background(), options.Timeout*3)
	defer cancel()

	resolver, err := dnsclient.NormalizeServer(options.Server)
	if err != nil {
		if options.JSON {
			WriteJSONError(stdout, "invalid_resolver", err.Error())
			return 1
		}
		fmt.Fprintf(stderr, "validate failed: %v\n", err)
		return 1
	}

	client := dnsclient.New(options.Timeout)
	bound := client.Bound(resolver, dnsclient.TransportUDP)
	validator := dnssec.NewValidator(anchors, bound)

	resp, elapsed, err := client.QueryWithDNSSEC(ctx, resolver, options.Domain, options.Qtype)
	if err != nil {
		if options.JSON {
			WriteJSONError(stdout, "query_failed", err.Error())
			return 1
		}
		fmt.Fprintf(stderr, "query failed: %v\n", err)
		return 1
	}

	result := validator.Validate(ctx, options.Domain, options.Qtype, resp)

	if options.JSON {
		out := validateJSONOutput{
			SchemaVersion: "1",
			Domain:        dns.Fqdn(options.Domain),
			Type:          dns.TypeToString[options.Qtype],
			Status:        string(result.Status),
			Reason:        result.Reason,
			Zone:          result.Zone,
			TrustAnchor:   result.TrustAnchor,
			ProofType:     result.ProofType,
			Wildcard:      result.Wildcard,
			Elapsed:       elapsed.String(),
			ElapsedMS:     float64(elapsed) / float64(time.Millisecond),
		}
		for _, ans := range resp.Answer {
			out.Answers = append(out.Answers, FormatAnswer(ans))
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(out)
	} else {
		fmt.Fprintf(stdout, "Validation: %s\n", strings.ToUpper(string(result.Status)))
		fmt.Fprintf(stdout, "Domain: %s %s\n", dns.Fqdn(options.Domain), dns.TypeToString[options.Qtype])
		fmt.Fprintf(stdout, "Reason: %s\n", result.Reason)
		if result.Zone != "" {
			fmt.Fprintf(stdout, "Zone: %s\n", result.Zone)
		}
		if result.TrustAnchor != "" {
			fmt.Fprintf(stdout, "Trust Anchor: %s\n", result.TrustAnchor)
		}
		if result.ProofType != "" {
			fmt.Fprintf(stdout, "Proof Type: %s\n", result.ProofType)
		}
		if result.Wildcard {
			fmt.Fprintf(stdout, "Wildcard Synthesis: yes\n")
		}
		fmt.Fprintf(stdout, "Elapsed: %s\n", elapsed.Round(time.Microsecond))
	}

	switch result.Status {
	case dnssec.StatusSecure:
		return 0
	case dnssec.StatusInsecure:
		return 3
	case dnssec.StatusBogus:
		return 5
	default:
		return 4
	}
}

// PrintValidateUsage outputs usage for validate.
func PrintValidateUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: dnsvet validate <domain> [--server <address>] [--type <record>] [--anchor <file>] [--timeout <duration>] [--json]")
}

// ParseValidateOptions parses validate command line flags.
func ParseValidateOptions(args []string) (QueryOptions, string, error) {
	options := QueryOptions{
		Server:  "1.1.1.1",
		Qtype:   dns.TypeA,
		Timeout: 5 * time.Second,
	}
	anchorPath := ""
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
			return options, "", fmt.Errorf("help requested")
		case "-s", "--server":
			val, err := scanner.ConsumeValue(name, value, hasValue)
			if err != nil {
				return options, "", err
			}
			norm, err := ParseNormalizedServer(val)
			if err != nil {
				return options, "", err
			}
			options.Server = norm
		case "-t", "--type":
			val, err := scanner.ConsumeValue(name, value, hasValue)
			if err != nil {
				return options, "", err
			}
			qtype, err := ParseSupportedQType(val)
			if err != nil {
				return options, "", err
			}
			options.Qtype = qtype
		case "--anchor":
			val, err := scanner.ConsumeValue(name, value, hasValue)
			if err != nil {
				return options, "", err
			}
			anchorPath = val
		case "--json":
			if hasValue {
				return options, "", fmt.Errorf("--json does not accept a value")
			}
			options.JSON = true
		case "--timeout":
			val, err := scanner.ConsumeValue(name, value, hasValue)
			if err != nil {
				return options, "", err
			}
			timeout, err := ParseBoundedTimeout(val)
			if err != nil {
				return options, "", err
			}
			options.Timeout = timeout
		default:
			return options, "", fmt.Errorf("unknown option %q", name)
		}
	}

	if len(positional) != 1 {
		return options, "", fmt.Errorf("expected exactly one domain name")
	}
	options.Domain = positional[0]
	return options, anchorPath, nil
}
