//go:build windows

package discovery

import (
	"fmt"
	"net"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// DiscoverResolvers queries Windows network configuration to find active DNS servers.
// It reads system TCP/IP parameters and interface settings without requiring administrative privileges.
func DiscoverResolvers() (*ResolverConfig, error) {
	config := &ResolverConfig{
		Servers:       make([]string, 0),
		SearchDomains: make([]string, 0),
		Source:        "windows_registry",
	}

	// 1. Read global TCP/IP parameters
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, registry.READ)
	if err == nil {
		defer k.Close()

		if ns, _, err := k.GetStringValue("NameServer"); err == nil && ns != "" {
			addServerList(&config.Servers, ns)
		}
		if dhcpNs, _, err := k.GetStringValue("DhcpNameServer"); err == nil && dhcpNs != "" {
			addServerList(&config.Servers, dhcpNs)
		}
		if searchList, _, err := k.GetStringValue("SearchList"); err == nil && searchList != "" {
			addDomainList(&config.SearchDomains, searchList)
		}
		if domain, _, err := k.GetStringValue("Domain"); err == nil && domain != "" {
			addDomainList(&config.SearchDomains, domain)
		}
		if dhcpDomain, _, err := k.GetStringValue("DhcpDomain"); err == nil && dhcpDomain != "" {
			addDomainList(&config.SearchDomains, dhcpDomain)
		}
	}

	// 2. Read per-interface TCP/IP parameters
	ik, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`, registry.READ)
	if err == nil {
		defer ik.Close()

		subkeys, err := ik.ReadSubKeyNames(-1)
		if err == nil {
			for _, subkey := range subkeys {
				ifaceKey, err := registry.OpenKey(ik, subkey, registry.READ)
				if err != nil {
					continue
				}
				if ns, _, err := ifaceKey.GetStringValue("NameServer"); err == nil && ns != "" {
					addServerList(&config.Servers, ns)
				}
				if dhcpNs, _, err := ifaceKey.GetStringValue("DhcpNameServer"); err == nil && dhcpNs != "" {
					addServerList(&config.Servers, dhcpNs)
				}
				if domain, _, err := ifaceKey.GetStringValue("Domain"); err == nil && domain != "" {
					addDomainList(&config.SearchDomains, domain)
				}
				if dhcpDomain, _, err := ifaceKey.GetStringValue("DhcpDomain"); err == nil && dhcpDomain != "" {
					addDomainList(&config.SearchDomains, dhcpDomain)
				}
				ifaceKey.Close()
			}
		}
	}

	if len(config.Servers) == 0 {
		return nil, fmt.Errorf("no configured DNS servers found in Windows configuration")
	}

	return config, nil
}

func addServerList(servers *[]string, list string) {
	// Delimited by space or comma
	fields := strings.FieldsFunc(list, func(r rune) bool {
		return r == ' ' || r == ',' || r == ';'
	})
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		ip := net.ParseIP(field)
		if ip != nil && !containsString(*servers, ip.String()) {
			*servers = append(*servers, ip.String())
		}
	}
}

func addDomainList(domains *[]string, list string) {
	fields := strings.FieldsFunc(list, func(r rune) bool {
		return r == ' ' || r == ',' || r == ';'
	})
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field != "" && !containsString(*domains, field) {
			*domains = append(*domains, field)
		}
	}
}
