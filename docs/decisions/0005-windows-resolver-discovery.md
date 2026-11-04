# ADR 0005: Windows resolver discovery via IP Helper API

- Status: Accepted
- Date: 2026-11-03

## Context

`dnsvet` requires local DNS resolver discovery across Windows, Linux, and macOS.
On Windows, configured DNS servers and suffix search lists can be retrieved through several methods:
1. Shelling out to `powershell.exe Get-DnsClientServerAddress` or `ipconfig /all`.
2. Reading registry keys under `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`.
3. Calling the Windows IP Helper Win32 API (`GetAdaptersAddresses`).

Shelling out introduces process creation overhead, execution policy restrictions, localization parsing issues, and failure modes when PowerShell or CMD is restricted. Reading the registry is fragile across Windows versions, VPN virtual adapters, and multi-homed configurations.

## Decision

Use the Windows IP Helper API via `golang.org/x/sys/windows` calling `GetAdaptersAddresses` with `GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST`.

Isolate this code in platform-specific files (`resolver_windows.go` with build tag `windows`). Provide portable fallback to standard system resolver lookups if API invocation returns an unexpected error.

## Consequences

- Direct, high-performance in-process query with no shell dependency.
- Works in standard non-privileged user contexts without administrator rights.
- Correctly enumerates IPv4 and IPv6 DNS server addresses in adapter preference order.
- Linux and macOS implementations will use `/etc/resolv.conf` parsing and platform conventions under corresponding build tags.
