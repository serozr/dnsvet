//go:build !windows

package discovery

import (
	"fmt"
	"os"
)

// DiscoverResolvers parses /etc/resolv.conf on Unix systems.
func DiscoverResolvers() (*ResolverConfig, error) {
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("failed to open /etc/resolv.conf: %w", err)
	}
	defer file.Close()

	config, err := ParseResolvConf(file)
	if err != nil {
		return nil, err
	}
	if len(config.Servers) == 0 {
		return nil, fmt.Errorf("no nameservers found in /etc/resolv.conf")
	}
	return config, nil
}
