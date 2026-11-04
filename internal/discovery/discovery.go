package discovery

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
)

// ResolverConfig contains discovered DNS resolver addresses and search domains.
type ResolverConfig struct {
	Servers       []string `json:"servers"`
	SearchDomains []string `json:"search_domains,omitempty"`
	Source        string   `json:"source"`
}

// ParseResolvConf parses resolver configuration from a resolv.conf format stream.
func ParseResolvConf(r io.Reader) (*ResolverConfig, error) {
	if r == nil {
		return nil, fmt.Errorf("reader must not be nil")
	}

	config := &ResolverConfig{
		Servers:       make([]string, 0),
		SearchDomains: make([]string, 0),
		Source:        "/etc/resolv.conf",
	}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		directive := strings.ToLower(fields[0])
		switch directive {
		case "nameserver":
			ip := net.ParseIP(fields[1])
			if ip != nil {
				config.Servers = append(config.Servers, ip.String())
			}
		case "domain":
			if len(config.SearchDomains) == 0 {
				config.SearchDomains = append(config.SearchDomains, fields[1])
			}
		case "search":
			for _, domain := range fields[1:] {
				domain = strings.TrimSpace(domain)
				if domain != "" && !containsString(config.SearchDomains, domain) {
					config.SearchDomains = append(config.SearchDomains, domain)
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading resolv.conf: %w", err)
	}

	return config, nil
}

func containsString(slice []string, val string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, val) {
			return true
		}
	}
	return false
}
