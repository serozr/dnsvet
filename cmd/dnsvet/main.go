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

	"github.com/serozr/dnsvet/internal/diagnostics"
	"github.com/serozr/dnsvet/internal/discovery"
	"github.com/serozr/dnsvet/internal/dnsclient"
	"github.com/serozr/dnsvet/internal/dnssec"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

type queryOptions struct {
	server    string
	qtype     uint16
	timeout   time.Duration
	domain    string
	transport dnsclient.Transport
	json      bool
	dnssec    bool
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
	case "validate":
		return runValidate(args[1:], stdout, stderr)
	case "discover":
		return runDiscover(args[1:], stdout, stderr)
	case "compare":
		return runCompare(args[1:], stdout, stderr)
	case "bench", "benchmark":
		return runBench(args[1:], stdout, stderr)
	case "leak", "hijack":
		return runLeak(args[1:], stdout, stderr)
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

	jsonRequested := jsonRequestedInArgs(args)
	options, err := parseQueryOptions(args)
	if err != nil {
		if jsonRequested {
			writeJSONError(stdout, "invalid_arguments", err.Error())
			return 2
		}
		fmt.Fprintf(stderr, "query: %v\n", err)
		printQueryUsage(stderr)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), options.timeout*2)
	defer cancel()

	resolver := options.server
	if options.transport == dnsclient.TransportUDP || options.transport == dnsclient.TransportTCP {
		normResolver, err := dnsclient.NormalizeServer(options.server)
		if err != nil {
			if options.json {
				writeJSONError(stdout, "invalid_resolver", err.Error())
				return 1
			}
			fmt.Fprintf(stderr, "DNS query failed: %v\n", err)
			return 1
		}
		resolver = normResolver
	}

	questionName, err := dnsclient.NormalizeDNSName(options.domain)
	if err != nil {
		if options.json {
			writeJSONError(stdout, "invalid_domain", err.Error())
			return 1
		}
		fmt.Fprintf(stderr, "DNS query failed: %v\n", err)
		return 1
	}
	questionName = dns.Fqdn(questionName)
	client := dnsclient.New(options.timeout)

	response, elapsed, err := client.QueryTransport(ctx, resolver, options.domain, options.qtype, options.transport, options.dnssec)
	if err != nil {
		if options.json {
			writeJSONError(stdout, "query_failed", err.Error())
			return 1
		}
		fmt.Fprintf(stderr, "DNS query failed: %v\n", err)
		return 1
	}

	if options.json {
		output := queryJSONOutput{
			SchemaVersion:   "1",
			Transport:       string(options.transport),
			DNSSECRequested: options.dnssec,
			Authenticated:   response.AuthenticatedData,
			LocalValidation: localValidationStatus(options.dnssec),
			Resolver:        resolver,
			Question:        questionName,
			Type:            dns.TypeToString[options.qtype],
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

	fmt.Fprintf(stdout, "Resolver: %s (transport: %s)\n", resolver, options.transport)
	fmt.Fprintf(stdout, "Question: %s %s\n", questionName, dns.TypeToString[options.qtype])
	rcode := dns.RcodeToString[response.Rcode]
	if rcode == "" {
		rcode = strconv.Itoa(response.Rcode)
	}
	fmt.Fprintf(stdout, "Response: %s (%d)\n", rcode, response.Rcode)
	fmt.Fprintf(stdout, "Elapsed: %s\n", elapsed.Round(time.Microsecond))
	if options.dnssec {
		fmt.Fprintf(stdout, "DNSSEC requested: yes (DO bit)\n")
		fmt.Fprintf(stdout, "Resolver AD bit: %t (resolver assertion; not locally validated)\n", response.AuthenticatedData)
	}

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

func runValidate(args []string, stdout, stderr io.Writer) int {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			printValidateUsage(stdout)
			return 0
		}
	}

	jsonRequested := jsonRequestedInArgs(args)
	options, anchorPath, err := parseValidateOptions(args)
	if err != nil {
		if jsonRequested {
			writeJSONError(stdout, "invalid_arguments", err.Error())
			return 2
		}
		fmt.Fprintf(stderr, "validate: %v\n", err)
		printValidateUsage(stderr)
		return 2
	}

	var anchors []dnssec.TrustAnchor
	if anchorPath != "" {
		f, err := os.Open(anchorPath)
		if err != nil {
			if jsonRequested {
				writeJSONError(stdout, "invalid_trust_anchor", err.Error())
				return 2
			}
			fmt.Fprintf(stderr, "failed to open trust anchor file %s: %v\n", anchorPath, err)
			return 2
		}
		defer f.Close()
		loaded, err := dnssec.LoadTrustAnchor(f)
		if err != nil {
			if jsonRequested {
				writeJSONError(stdout, "invalid_trust_anchor", err.Error())
				return 2
			}
			fmt.Fprintf(stderr, "failed to load trust anchor from %s: %v\n", anchorPath, err)
			return 2
		}
		anchors = []dnssec.TrustAnchor{loaded}
	} else {
		anchors = defaultRootTrustAnchors()
	}

	ctx, cancel := context.WithTimeout(context.Background(), options.timeout*3)
	defer cancel()

	resolver, err := dnsclient.NormalizeServer(options.server)
	if err != nil {
		if options.json {
			writeJSONError(stdout, "invalid_resolver", err.Error())
			return 1
		}
		fmt.Fprintf(stderr, "validate failed: %v\n", err)
		return 1
	}

	client := dnsclient.New(options.timeout)
	bound := client.Bound(resolver, dnsclient.TransportUDP)
	validator := dnssec.NewValidator(anchors, bound)

	resp, elapsed, err := client.QueryWithDNSSEC(ctx, resolver, options.domain, options.qtype)
	if err != nil {
		if options.json {
			writeJSONError(stdout, "query_failed", err.Error())
			return 1
		}
		fmt.Fprintf(stderr, "query failed: %v\n", err)
		return 1
	}

	result := validator.Validate(ctx, options.domain, options.qtype, resp)

	if options.json {
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
		out := validateJSONOutput{
			SchemaVersion: "1",
			Domain:        dns.Fqdn(options.domain),
			Type:          dns.TypeToString[options.qtype],
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
			out.Answers = append(out.Answers, formatAnswer(ans))
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(out)
	} else {
		fmt.Fprintf(stdout, "Validation: %s\n", strings.ToUpper(string(result.Status)))
		fmt.Fprintf(stdout, "Domain: %s %s\n", dns.Fqdn(options.domain), dns.TypeToString[options.qtype])
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
	case dnssec.StatusInsecure, dnssec.StatusBogus:
		return 3
	default:
		return 4
	}
}

func runDiscover(args []string, stdout, stderr io.Writer) int {
	jsonRequested := jsonRequestedInArgs(args)
	config, err := discovery.DiscoverResolvers()
	if err != nil {
		if jsonRequested {
			writeJSONError(stdout, "discovery_failed", err.Error())
			return 1
		}
		fmt.Fprintf(stderr, "resolver discovery failed: %v\n", err)
		return 1
	}

	if jsonRequested {
		type discoverJSONOutput struct {
			SchemaVersion string   `json:"schema_version"`
			Source        string   `json:"source"`
			Servers       []string `json:"servers"`
			SearchDomains []string `json:"search_domains,omitempty"`
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(discoverJSONOutput{
			SchemaVersion: "1",
			Source:        config.Source,
			Servers:       config.Servers,
			SearchDomains: config.SearchDomains,
		})
		return 0
	}

	fmt.Fprintf(stdout, "Discovered DNS Resolvers:\n")
	fmt.Fprintf(stdout, "  Source: %s\n", config.Source)
	fmt.Fprintf(stdout, "  Nameservers (%d):\n", len(config.Servers))
	for _, s := range config.Servers {
		fmt.Fprintf(stdout, "    - %s\n", s)
	}
	if len(config.SearchDomains) > 0 {
		fmt.Fprintf(stdout, "  Search Domains:\n")
		for _, d := range config.SearchDomains {
			fmt.Fprintf(stdout, "    - %s\n", d)
		}
	}
	return 0
}

func runCompare(args []string, stdout, stderr io.Writer) int {
	jsonRequested := jsonRequestedInArgs(args)
	domain, qtype, resolvers, timeout, jsonOutput, err := parseCompareOptions(args)
	if err != nil {
		if jsonRequested {
			writeJSONError(stdout, "invalid_arguments", err.Error())
			return 2
		}
		fmt.Fprintf(stderr, "compare: %v\n", err)
		printCompareUsage(stderr)
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
	result, err := diagnostics.CompareResolvers(ctx, client, resolvers, domain, qtype)
	if err != nil {
		if jsonOutput {
			writeJSONError(stdout, "compare_failed", err.Error())
			return 1
		}
		fmt.Fprintf(stderr, "comparison failed: %v\n", err)
		return 1
	}

	if jsonOutput {
		type compareJSONEnvelope struct {
			SchemaVersion string                        `json:"schema_version"`
			Comparison    *diagnostics.ComparisonResult `json:"comparison"`
		}
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
		if result.Consistent {
			fmt.Fprintln(stdout, "\nConsistency: CONSISTENT (all resolvers agree)")
		} else {
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

func runBench(args []string, stdout, stderr io.Writer) int {
	jsonRequested := jsonRequestedInArgs(args)
	domain, qtype, server, count, timeout, jsonOutput, err := parseBenchOptions(args)
	if err != nil {
		if jsonRequested {
			writeJSONError(stdout, "invalid_arguments", err.Error())
			return 2
		}
		fmt.Fprintf(stderr, "bench: %v\n", err)
		printBenchUsage(stderr)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout*time.Duration(count+2))
	defer cancel()

	client := dnsclient.New(timeout)
	stats, err := diagnostics.BenchmarkResolver(ctx, client, server, domain, qtype, count)
	if err != nil {
		if jsonOutput {
			writeJSONError(stdout, "bench_failed", err.Error())
			return 1
		}
		fmt.Fprintf(stderr, "benchmark failed: %v\n", err)
		return 1
	}

	if jsonOutput {
		type benchJSONEnvelope struct {
			SchemaVersion string                      `json:"schema_version"`
			Benchmark     *diagnostics.BenchmarkStats `json:"benchmark"`
		}
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

func runLeak(args []string, stdout, stderr io.Writer) int {
	jsonRequested := jsonRequestedInArgs(args)
	server, timeout, jsonOutput, err := parseLeakOptions(args)
	if err != nil {
		if jsonRequested {
			writeJSONError(stdout, "invalid_arguments", err.Error())
			return 2
		}
		fmt.Fprintf(stderr, "leak: %v\n", err)
		printLeakUsage(stderr)
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout*5)
	defer cancel()

	client := dnsclient.New(timeout)
	result, err := diagnostics.DetectHijackingAndLeaks(ctx, client, server)
	if err != nil {
		if jsonOutput {
			writeJSONError(stdout, "leak_check_failed", err.Error())
			return 1
		}
		fmt.Fprintf(stderr, "leak check failed: %v\n", err)
		return 1
	}

	if jsonOutput {
		type leakJSONEnvelope struct {
			SchemaVersion string                  `json:"schema_version"`
			LeakReport    *diagnostics.LeakResult `json:"leak_report"`
		}
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

func defaultRootTrustAnchors() []dnssec.TrustAnchor {
	ksk2017 := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 172800},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
		PublicKey: "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
	}
	return []dnssec.TrustAnchor{
		{
			Zone:    ".",
			DNSKEY:  ksk2017,
			DNSKEYs: []*dns.DNSKEY{ksk2017},
		},
	}
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

type queryJSONError struct {
	SchemaVersion string          `json:"schema_version"`
	Error         queryJSONDetail `json:"error"`
}

type queryJSONDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSONError(w io.Writer, code, message string) {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(queryJSONError{
		SchemaVersion: "1",
		Error:         queryJSONDetail{Code: code, Message: message},
	})
}

func jsonRequestedInArgs(args []string) bool {
	for _, arg := range args {
		name, _, _ := strings.Cut(arg, "=")
		if name == "--json" {
			return true
		}
	}
	return false
}

func localValidationStatus(requested bool) string {
	if !requested {
		return ""
	}
	return "not_performed"
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

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "dnsvet - DNS diagnostics and security toolkit")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  dnsvet <command> [options]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  query       Query a DNS record over UDP, TCP, DoT, or DoH")
	fmt.Fprintln(w, "  validate    Cryptographically validate DNSSEC chain of trust")
	fmt.Fprintln(w, "  discover    Discover system-configured DNS resolvers")
	fmt.Fprintln(w, "  compare     Compare answers across multiple resolvers")
	fmt.Fprintln(w, "  bench       Benchmark resolver latency and reliability")
	fmt.Fprintln(w, "  leak        Detect DNS hijacking and NXDOMAIN rewriting")
	fmt.Fprintln(w, "  version     Show version and build information")
	fmt.Fprintln(w, "  help        Show this help message")
}

func printQueryUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: dnsvet query <domain> [--server <address>] [--type <record>] [--transport <udp|tcp|tls|https>] [--timeout <duration>] [--dnssec] [--json]")
	fmt.Fprintln(w, "Supported types: A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT, CAA, DS, DNSKEY, RRSIG, NSEC, NSEC3")
}

func printValidateUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: dnsvet validate <domain> [--server <address>] [--type <record>] [--anchor <file>] [--timeout <duration>] [--json]")
}

func printCompareUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: dnsvet compare <domain> [--servers <addr1,addr2,...>] [--type <record>] [--timeout <duration>] [--json]")
}

func printBenchUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: dnsvet bench <domain> [--server <address>] [--count <number>] [--type <record>] [--timeout <duration>] [--json]")
}

func printLeakUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: dnsvet leak [--server <address>] [--timeout <duration>] [--json]")
}

func parseQueryOptions(args []string) (queryOptions, error) {
	options := queryOptions{
		server:    "1.1.1.1",
		qtype:     dns.TypeA,
		timeout:   3 * time.Second,
		transport: dnsclient.TransportUDP,
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
		case "--transport":
			if !hasValue {
				i++
				if i >= len(args) {
					return options, fmt.Errorf("%s requires a value", name)
				}
				value = args[i]
			}
			switch strings.ToLower(value) {
			case "udp":
				options.transport = dnsclient.TransportUDP
			case "tcp":
				options.transport = dnsclient.TransportTCP
			case "tls", "dot":
				options.transport = dnsclient.TransportTLS
			case "https", "doh":
				options.transport = dnsclient.TransportHTTPS
			default:
				return options, fmt.Errorf("unsupported transport %q: use udp, tcp, tls, or https", value)
			}
		case "--dnssec":
			if hasValue {
				return options, fmt.Errorf("--dnssec does not accept a value")
			}
			options.dnssec = true
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

func parseValidateOptions(args []string) (queryOptions, string, error) {
	options := queryOptions{
		server:  "1.1.1.1",
		qtype:   dns.TypeA,
		timeout: 5 * time.Second,
	}
	anchorPath := ""
	var positional []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		name, value, hasValue := strings.Cut(arg, "=")
		switch name {
		case "-h", "--help":
			return options, "", fmt.Errorf("help requested")
		case "-s", "--server":
			if !hasValue {
				i++
				if i >= len(args) {
					return options, "", fmt.Errorf("%s requires a value", name)
				}
				value = args[i]
			}
			options.server = value
		case "-t", "--type":
			if !hasValue {
				i++
				if i >= len(args) {
					return options, "", fmt.Errorf("%s requires a value", name)
				}
				value = args[i]
			}
			qtype, ok := dns.StringToType[strings.ToUpper(value)]
			if !ok || !isSupportedQueryType(qtype) {
				return options, "", fmt.Errorf("unsupported DNS record type %q", value)
			}
			options.qtype = qtype
		case "--anchor":
			if !hasValue {
				i++
				if i >= len(args) {
					return options, "", fmt.Errorf("%s requires a value", name)
				}
				value = args[i]
			}
			anchorPath = value
		case "--json":
			if hasValue {
				return options, "", fmt.Errorf("--json does not accept a value")
			}
			options.json = true
		case "--timeout":
			if !hasValue {
				i++
				if i >= len(args) {
					return options, "", fmt.Errorf("%s requires a value", name)
				}
				value = args[i]
			}
			timeout, err := time.ParseDuration(value)
			if err != nil || timeout <= 0 || timeout > 60*time.Second {
				return options, "", fmt.Errorf("invalid timeout %q: use duration up to 60s", value)
			}
			options.timeout = timeout
		default:
			if strings.HasPrefix(arg, "-") {
				return options, "", fmt.Errorf("unknown option %q", arg)
			}
			positional = append(positional, arg)
		}
	}

	if len(positional) != 1 {
		return options, "", fmt.Errorf("expected exactly one domain name")
	}
	options.domain = positional[0]
	return options, anchorPath, nil
}

func parseCompareOptions(args []string) (string, uint16, []string, time.Duration, bool, error) {
	qtype := dns.TypeA
	timeout := 3 * time.Second
	jsonOutput := false
	var resolvers []string
	var positional []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		name, value, hasValue := strings.Cut(arg, "=")
		switch name {
		case "-h", "--help":
			return "", 0, nil, 0, false, fmt.Errorf("help requested")
		case "-t", "--type":
			if !hasValue {
				i++
				if i >= len(args) {
					return "", 0, nil, 0, false, fmt.Errorf("%s requires a value", name)
				}
				value = args[i]
			}
			t, ok := dns.StringToType[strings.ToUpper(value)]
			if !ok {
				return "", 0, nil, 0, false, fmt.Errorf("unsupported type %q", value)
			}
			qtype = t
		case "-s", "--servers", "--server":
			if !hasValue {
				i++
				if i >= len(args) {
					return "", 0, nil, 0, false, fmt.Errorf("%s requires a value", name)
				}
				value = args[i]
			}
			for _, s := range strings.Split(value, ",") {
				s = strings.TrimSpace(s)
				if s != "" {
					resolvers = append(resolvers, s)
				}
			}
		case "--json":
			jsonOutput = true
		case "--timeout":
			if !hasValue {
				i++
				if i >= len(args) {
					return "", 0, nil, 0, false, fmt.Errorf("%s requires a value", name)
				}
				value = args[i]
			}
			dur, err := time.ParseDuration(value)
			if err != nil || dur <= 0 {
				return "", 0, nil, 0, false, fmt.Errorf("invalid timeout %q", value)
			}
			timeout = dur
		default:
			if strings.HasPrefix(arg, "-") {
				return "", 0, nil, 0, false, fmt.Errorf("unknown option %q", arg)
			}
			positional = append(positional, arg)
		}
	}
	if len(positional) != 1 {
		return "", 0, nil, 0, false, fmt.Errorf("expected exactly one domain name")
	}
	return positional[0], qtype, resolvers, timeout, jsonOutput, nil
}

func parseBenchOptions(args []string) (string, uint16, string, int, time.Duration, bool, error) {
	qtype := dns.TypeA
	server := "1.1.1.1"
	count := 10
	timeout := 3 * time.Second
	jsonOutput := false
	var positional []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		name, value, hasValue := strings.Cut(arg, "=")
		switch name {
		case "-h", "--help":
			return "", 0, "", 0, 0, false, fmt.Errorf("help requested")
		case "-s", "--server":
			if !hasValue {
				i++
				if i >= len(args) {
					return "", 0, "", 0, 0, false, fmt.Errorf("%s requires a value", name)
				}
				value = args[i]
			}
			server = value
		case "-c", "--count":
			if !hasValue {
				i++
				if i >= len(args) {
					return "", 0, "", 0, 0, false, fmt.Errorf("%s requires a value", name)
				}
				value = args[i]
			}
			n, err := strconv.Atoi(value)
			if err != nil || n <= 0 || n > 100 {
				return "", 0, "", 0, 0, false, fmt.Errorf("invalid count %q: must be between 1 and 100", value)
			}
			count = n
		case "-t", "--type":
			if !hasValue {
				i++
				if i >= len(args) {
					return "", 0, "", 0, 0, false, fmt.Errorf("%s requires a value", name)
				}
				value = args[i]
			}
			t, ok := dns.StringToType[strings.ToUpper(value)]
			if !ok {
				return "", 0, "", 0, 0, false, fmt.Errorf("unsupported type %q", value)
			}
			qtype = t
		case "--json":
			jsonOutput = true
		case "--timeout":
			if !hasValue {
				i++
				if i >= len(args) {
					return "", 0, "", 0, 0, false, fmt.Errorf("%s requires a value", name)
				}
				value = args[i]
			}
			dur, err := time.ParseDuration(value)
			if err != nil || dur <= 0 {
				return "", 0, "", 0, 0, false, fmt.Errorf("invalid timeout %q", value)
			}
			timeout = dur
		default:
			if strings.HasPrefix(arg, "-") {
				return "", 0, "", 0, 0, false, fmt.Errorf("unknown option %q", arg)
			}
			positional = append(positional, arg)
		}
	}
	if len(positional) != 1 {
		return "", 0, "", 0, 0, false, fmt.Errorf("expected exactly one domain name")
	}
	return positional[0], qtype, server, count, timeout, jsonOutput, nil
}

func parseLeakOptions(args []string) (string, time.Duration, bool, error) {
	server := "1.1.1.1"
	timeout := 3 * time.Second
	jsonOutput := false

	for i := 0; i < len(args); i++ {
		arg := args[i]
		name, value, hasValue := strings.Cut(arg, "=")
		switch name {
		case "-h", "--help":
			return "", 0, false, fmt.Errorf("help requested")
		case "-s", "--server":
			if !hasValue {
				i++
				if i >= len(args) {
					return "", 0, false, fmt.Errorf("%s requires a value", name)
				}
				value = args[i]
			}
			server = value
		case "--json":
			jsonOutput = true
		case "--timeout":
			if !hasValue {
				i++
				if i >= len(args) {
					return "", 0, false, fmt.Errorf("%s requires a value", name)
				}
				value = args[i]
			}
			dur, err := time.ParseDuration(value)
			if err != nil || dur <= 0 {
				return "", 0, false, fmt.Errorf("invalid timeout %q", value)
			}
			timeout = dur
		default:
			if strings.HasPrefix(arg, "-") {
				return "", 0, false, fmt.Errorf("unknown option %q", arg)
			}
		}
	}
	return server, timeout, jsonOutput, nil
}
