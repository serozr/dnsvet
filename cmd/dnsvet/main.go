package main

import (
	"os"

	"github.com/serozr/dnsvet/internal/cli"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	cli.Version = version
	cli.Commit = commit
	cli.BuildDate = buildDate
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
