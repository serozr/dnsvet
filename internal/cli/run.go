package cli

import (
	"fmt"
	"io"
	"runtime"
)

var (
	// Version is populated at build time via -ldflags.
	Version = "dev"
	// Commit is populated at build time via -ldflags.
	Commit = "unknown"
	// BuildDate is populated at build time via -ldflags.
	BuildDate = "unknown"
)

// Run executes the CLI with the supplied arguments and I/O streams.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		PrintUsage(stdout)
		return 0
	}

	switch args[0] {
	case "help", "--help", "-h":
		PrintUsage(stdout)
		return 0
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "dnsvet %s\n", Version)
		fmt.Fprintf(stdout, "Commit: %s\n", Commit)
		fmt.Fprintf(stdout, "Built: %s\n", BuildDate)
		fmt.Fprintf(stdout, "Go: %s\n", runtime.Version())
		fmt.Fprintf(stdout, "Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		return 0
	case "query":
		return RunQuery(args[1:], stdout, stderr)
	case "validate":
		return RunValidate(args[1:], stdout, stderr)
	case "discover":
		return RunDiscover(args[1:], stdout, stderr)
	case "compare":
		return RunCompare(args[1:], stdout, stderr)
	case "bench", "benchmark":
		return RunBench(args[1:], stdout, stderr)
	case "leak", "hijack":
		return RunLeak(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n\n", args[0])
		PrintUsage(stderr)
		return 2
	}
}

// PrintUsage outputs the main CLI usage summary.
func PrintUsage(w io.Writer) {
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
	fmt.Fprintln(w, "  leak        Check for DNS hijacking and NXDOMAIN rewriting")
	fmt.Fprintln(w, "  version     Show version and build information")
	fmt.Fprintln(w, "  help        Show this help message")
}
