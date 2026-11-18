package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/serozr/dnsvet/internal/discovery"
)

type discoverJSONOutput struct {
	SchemaVersion string   `json:"schema_version"`
	Source        string   `json:"source"`
	Servers       []string `json:"servers"`
	SearchDomains []string `json:"search_domains,omitempty"`
}

// RunDiscover executes the discover subcommand.
func RunDiscover(args []string, stdout, stderr io.Writer) int {
	jsonRequested := JSONRequestedInArgs(args)
	config, err := discovery.DiscoverResolvers()
	if err != nil {
		if jsonRequested {
			WriteJSONError(stdout, "discovery_failed", err.Error())
			return 1
		}
		fmt.Fprintf(stderr, "resolver discovery failed: %v\n", err)
		return 1
	}

	if jsonRequested {
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
