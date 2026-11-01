package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/serozr/dnsvet/internal/dnsclient"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

type queryOptions struct {
	server  string
	qtype   uint16
	timeout time.Duration
	domain  string
	json    bool
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stdout)
		return 0
	}

	switch args[0] {
	case "help", "--help", "-h":
		printUsage(stdout)
		return 0
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "dnsvet %s\n", version)
		fmt.Fprintf(stdout, "Commit: %s\n", commit)
		fmt.Fprintf(stdout, "Built: %s\n", buildDate)
		fmt.Fprintf(stdout, "Go: %s\n", runtime.Version())
		fmt.Fprintf(stdout, "Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		return 0
	case "query":
		return runQuery(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func runQuery(args []string, stdout, stderr io.Writer) int {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			printQueryUsage(stdout)
			return 0
		}
	}

	options, err := parseQueryOptions(args)
	if err != nil {
		fmt.Fprintf(stderr, "query: %v\n", err)
		printQueryUsage(stderr)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), options.timeout*2)
	defer cancel()

	resolver, err := dnsclient.NormalizeServer(options.server)
	if err != nil {
		fmt.Fprintf(stderr, "DNS query failed: %v\n", err)
		return 1
	}
	response, elapsed, err := dnsclient.New(options.timeout).Query(ctx, resolver, options.domain, options.qtype)
	if err != nil {
		fmt.Fprintf(stderr, "DNS query failed: %v\n", err)
		return 1
	}

	if options.json {
		output := queryJSONOutput{
			Resolver: resolver,
			Question: dns.Fqdn(options.domain),
			Type:     dns.TypeToString[options.qtype],
			Response: dns.RcodeToString[response.Rcode],
			RCode:    response.Rcode,
			Elapsed:  elapsed.String(),
			Answers:  make([]string, 0, len(response.Answer)),
		}
		if output.Response == "" {
			output.Response = strconv.Itoa(response.Rcode)
		}
		for _, answer := range response.Answer {
			output.Answers = append(output.Answers, formatAnswer(answer))
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(output); err != nil {
			fmt.Fprintf(stderr, "failed to encode JSON response: %v\n", err)
			return 1
		}
		return 0
	}

	fmt.Fprintf(stdout, "Resolver: %s\n", resolver)
	fmt.Fprintf(stdout, "Question: %s %s\n", dns.Fqdn(options.domain), dns.TypeToString[options.qtype])
	rcode := dns.RcodeToString[response.Rcode]
	if rcode == "" {
		rcode = strconv.Itoa(response.Rcode)
	}
	fmt.Fprintf(stdout, "Response: %s (%d)\n", rcode, response.Rcode)
	fmt.Fprintf(stdout, "Elapsed: %s\n", elapsed.Round(time.Microsecond))

	if len(response.Answer) == 0 {
		fmt.Fprintln(stdout, "Answers: none")
		return 0
	}

	fmt.Fprintln(stdout, "Answers:")
	for _, answer := range response.Answer {
		fmt.Fprintf(stdout, "  %s\n", formatAnswer(answer))
	}
	return 0
}

type queryJSONOutput struct {
	Resolver string   `json:"resolver"`
	Question string   `json:"question"`
	Type     string   `json:"type"`
	Response string   `json:"response"`
	RCode    int      `json:"rcode"`
	Elapsed  string   `json:"elapsed"`
	Answers  []string `json:"answers"`
}

func formatAnswer(record dns.RR) string {
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

func isSupportedQueryType(qtype uint16) bool {
	switch qtype {
	case dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeMX, dns.TypeNS,
		dns.TypePTR, dns.TypeSOA, dns.TypeSRV, dns.TypeTXT, dns.TypeCAA,
		dns.TypeDS, dns.TypeDNSKEY, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3:
		return true
	default:
		return false
	}
}

func printQueryUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: dnsvet query <domain> [--server <address>] [--type <record>] [--timeout <duration>] [--json]")
	fmt.Fprintln(w, "Supported types: A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT, CAA, DS, DNSKEY, RRSIG, NSEC, NSEC3")
}

func parseQueryOptions(args []string) (queryOptions, error) {
	options := queryOptions{
		server:  "1.1.1.1",
		qtype:   dns.TypeA,
		timeout: 3 * time.Second,
	}
	var positional []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		name, value, hasValue := strings.Cut(arg, "=")
		switch name {
		case "-h", "--help":
			return options, fmt.Errorf("help requested")
		case "-s", "--server":
			if !hasValue {
				i++
				if i >= len(args) {
					return options, fmt.Errorf("%s requires a value", name)
				}
				value = args[i]
			}
			options.server = value
		case "-t", "--type":
			if !hasValue {
				i++
				if i >= len(args) {
					return options, fmt.Errorf("%s requires a value", name)
				}
				value = args[i]
			}
			qtype, ok := dns.StringToType[strings.ToUpper(value)]
			if !ok || !isSupportedQueryType(qtype) {
				return options, fmt.Errorf("unsupported DNS record type %q", value)
			}
			options.qtype = qtype
		case "--json":
			if hasValue {
				return options, fmt.Errorf("--json does not accept a value")
			}
			options.json = true
		case "--timeout":
			if !hasValue {
				i++
				if i >= len(args) {
					return options, fmt.Errorf("%s requires a value", name)
				}
				value = args[i]
			}
			timeout, err := time.ParseDuration(value)
			if err != nil || timeout <= 0 || timeout > 60*time.Second {
				return options, fmt.Errorf("invalid timeout %q: use a positive duration up to 60s, such as 2s", value)
			}
			options.timeout = timeout
		default:
			if strings.HasPrefix(arg, "-") {
				return options, fmt.Errorf("unknown option %q", arg)
			}
			positional = append(positional, arg)
		}
	}

	if len(positional) != 1 {
		return options, fmt.Errorf("expected exactly one domain name")
	}
	options.domain = positional[0]
	if strings.TrimSpace(options.server) == "" {
		return options, fmt.Errorf("resolver address must not be empty")
	}
	return options, nil
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "dnsvet - DNS diagnostics toolkit")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  dnsvet <command>")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  help      Show this help")
	fmt.Fprintln(w, "  version   Show version and build information")
	fmt.Fprintln(w, "  query     Query a DNS record")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Query usage:")
	fmt.Fprintln(w, "  dnsvet query <domain> [--server <address>] [--type <record>] [--timeout <duration>] [--json]")
	fmt.Fprintln(w, "  dnsvet query example.com --server 1.1.1.1 --type A")
	fmt.Fprintln(w, "  dnsvet query example.com --json")
}
