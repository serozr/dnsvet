package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/serozr/dnsvet/internal/dnsclient"
)

// QueryOptions holds parsed parameters for the query command.
type QueryOptions struct {
	Server    string
	Qtype     uint16
	Timeout   time.Duration
	Domain    string
	Transport dnsclient.Transport
	JSON      bool
	DNSSEC    bool
}

type queryJSONOutput struct {
	SchemaVersion   string   `json:"schema_version"`
	Transport       string   `json:"transport,omitempty"`
	Resolver        string   `json:"resolver"`
	Question        string   `json:"question"`
	Type            string   `json:"type"`
	Response        string   `json:"response"`
	RCode           int      `json:"rcode"`
	Elapsed         string   `json:"elapsed"`
	ElapsedMS       float64  `json:"elapsed_ms"`
	Answers         []string `json:"answers"`
	DNSSECRequested bool     `json:"dnssec_requested"`
	Authenticated   bool     `json:"authenticated_data"`
	LocalValidation string   `json:"local_validation,omitempty"`
}

// RunQuery executes the query subcommand.
func RunQuery(args []string, stdout, stderr io.Writer) int {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			PrintQueryUsage(stdout)
			return 0
		}
	}

	jsonRequested := JSONRequestedInArgs(args)
	options, err := ParseQueryOptions(args)
	if err != nil {
		if jsonRequested {
			WriteJSONError(stdout, "invalid_arguments", err.Error())
			return 2
		}
		fmt.Fprintf(stderr, "query: %v\n", err)
		PrintQueryUsage(stderr)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), options.Timeout*2)
	defer cancel()

	resolver := options.Server
	if options.Transport == dnsclient.TransportUDP || options.Transport == dnsclient.TransportTCP {
		normResolver, err := dnsclient.NormalizeServer(options.Server)
		if err != nil {
			if options.JSON {
				WriteJSONError(stdout, "invalid_resolver", err.Error())
				return 1
			}
			fmt.Fprintf(stderr, "DNS query failed: %v\n", err)
			return 1
		}
		resolver = normResolver
	}

	questionName, err := dnsclient.NormalizeDNSName(options.Domain)
	if err != nil {
		if options.JSON {
			WriteJSONError(stdout, "invalid_domain", err.Error())
			return 1
		}
		fmt.Fprintf(stderr, "DNS query failed: %v\n", err)
		return 1
	}
	questionName = dns.Fqdn(questionName)
	client := dnsclient.New(options.Timeout)

	response, elapsed, err := client.QueryTransport(ctx, resolver, options.Domain, options.Qtype, options.Transport, options.DNSSEC)
	if err != nil {
		if options.JSON {
			WriteJSONError(stdout, "query_failed", err.Error())
			return 1
		}
		fmt.Fprintf(stderr, "DNS query failed: %v\n", err)
		return 1
	}

	if options.JSON {
		output := queryJSONOutput{
			SchemaVersion:   "1",
			Transport:       string(options.Transport),
			DNSSECRequested: options.DNSSEC,
			Authenticated:   response.AuthenticatedData,
			LocalValidation: LocalValidationStatus(options.DNSSEC),
			Resolver:        resolver,
			Question:        questionName,
			Type:            dns.TypeToString[options.Qtype],
			Response:        dns.RcodeToString[response.Rcode],
			RCode:           response.Rcode,
			Elapsed:         elapsed.String(),
			ElapsedMS:       float64(elapsed) / float64(time.Millisecond),
			Answers:         make([]string, 0, len(response.Answer)),
		}
		if output.Response == "" {
			output.Response = strconv.Itoa(response.Rcode)
		}
		for _, answer := range response.Answer {
			output.Answers = append(output.Answers, FormatAnswer(answer))
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(output); err != nil {
			fmt.Fprintf(stderr, "failed to encode JSON response: %v\n", err)
			return 1
		}
		return 0
	}

	fmt.Fprintf(stdout, "Resolver: %s (transport: %s)\n", resolver, options.Transport)
	fmt.Fprintf(stdout, "Question: %s %s\n", questionName, dns.TypeToString[options.Qtype])
	rcode := dns.RcodeToString[response.Rcode]
	if rcode == "" {
		rcode = strconv.Itoa(response.Rcode)
	}
	fmt.Fprintf(stdout, "Response: %s (%d)\n", rcode, response.Rcode)
	fmt.Fprintf(stdout, "Elapsed: %s\n", elapsed.Round(time.Microsecond))
	if options.DNSSEC {
		fmt.Fprintf(stdout, "DNSSEC requested: yes (DO bit)\n")
		fmt.Fprintf(stdout, "Resolver AD bit: %t (resolver assertion; not locally validated)\n", response.AuthenticatedData)
	}

	if len(response.Answer) == 0 {
		fmt.Fprintln(stdout, "Answers: none")
		return 0
	}

	fmt.Fprintln(stdout, "Answers:")
	for _, answer := range response.Answer {
		fmt.Fprintf(stdout, "  %s\n", FormatAnswer(answer))
	}
	return 0
}

// PrintQueryUsage prints help for query.
func PrintQueryUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: dnsvet query <domain> [--server <address>] [--type <record>] [--transport <udp|tcp|tls|https>] [--timeout <duration>] [--dnssec] [--json]")
	fmt.Fprintln(w, "Supported types: A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT, CAA, DS, DNSKEY, RRSIG, NSEC, NSEC3")
}

// ParseQueryOptions parses query command line flags.
func ParseQueryOptions(args []string) (QueryOptions, error) {
	options := QueryOptions{
		Server:    "1.1.1.1",
		Qtype:     dns.TypeA,
		Timeout:   3 * time.Second,
		Transport: dnsclient.TransportUDP,
	}
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
			return options, fmt.Errorf("help requested")
		case "-s", "--server":
			val, err := scanner.ConsumeValue(name, value, hasValue)
			if err != nil {
				return options, err
			}
			options.Server = val
		case "-t", "--type":
			val, err := scanner.ConsumeValue(name, value, hasValue)
			if err != nil {
				return options, err
			}
			qtype, err := ParseSupportedQType(val)
			if err != nil {
				return options, err
			}
			options.Qtype = qtype
		case "--transport":
			val, err := scanner.ConsumeValue(name, value, hasValue)
			if err != nil {
				return options, err
			}
			switch strings.ToLower(val) {
			case "udp":
				options.Transport = dnsclient.TransportUDP
			case "tcp":
				options.Transport = dnsclient.TransportTCP
			case "tls", "dot":
				options.Transport = dnsclient.TransportTLS
			case "https", "doh":
				options.Transport = dnsclient.TransportHTTPS
			default:
				return options, fmt.Errorf("unsupported transport %q: use udp, tcp, tls, or https", val)
			}
		case "--dnssec":
			if hasValue {
				return options, fmt.Errorf("--dnssec does not accept a value")
			}
			options.DNSSEC = true
		case "--json":
			if hasValue {
				return options, fmt.Errorf("--json does not accept a value")
			}
			options.JSON = true
		case "--timeout":
			val, err := scanner.ConsumeValue(name, value, hasValue)
			if err != nil {
				return options, err
			}
			timeout, err := ParseBoundedTimeout(val)
			if err != nil {
				return options, err
			}
			options.Timeout = timeout
		default:
			return options, fmt.Errorf("unknown option %q", name)
		}
	}

	if len(positional) != 1 {
		return options, fmt.Errorf("expected exactly one domain name")
	}
	options.Domain = positional[0]
	if strings.TrimSpace(options.Server) == "" {
		return options, fmt.Errorf("resolver address must not be empty")
	}
	return options, nil
}
