package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

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
		fmt.Fprintf(stdout, "ResolverGuard %s\n", version)
		fmt.Fprintf(stdout, "Commit: %s\n", commit)
		fmt.Fprintf(stdout, "Built: %s\n", buildDate)
		fmt.Fprintf(stdout, "Go: %s\n", runtime.Version())
		fmt.Fprintf(stdout, "Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "ResolverGuard - DNS diagnostics toolkit")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  resolverguard <command>")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  help      Show this help")
	fmt.Fprintln(w, "  version   Show version and build information")
}
