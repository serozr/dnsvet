# dnsvet

**dnsvet** is an open-source DNS diagnostics and intelligence toolkit written in Go.

It is being built to inspect DNS resolver configuration, query behavior, availability, performance, privacy characteristics, and security indicators through a cross-platform command-line interface.

> **Status:** Early development. Most planned capabilities are not implemented yet.

## Goals

- Windows, Linux, and macOS support.
- Local-first operation with no AI dependency.
- DNS diagnostics based on explicit, testable rules.
- Safe defaults, bounded timeouts, and controlled query rates.
- Readable terminal output and machine-readable JSON.
- Unit and local integration tests that do not depend on public DNS services.

## Planned capabilities

- DNS record queries over UDP and TCP, with optional EDNS DNSSEC (DO-bit) requests.
- Resolver discovery from operating-system configuration.
- Resolver benchmarking and comparison.
- DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT).
- DNSSEC, DNS leak, NXDOMAIN consistency, and rewriting indicators.
- DNS trace, propagation, and infrastructure diagnostics.
- Terminal, JSON, and eventually HTML reports.

Features will be documented as implemented only after they have working tests.

The current DNSSEC package contains validation primitives for RRsets, DS/DNSKEY matching, trust anchors, supplied delegation chains, and a bounded parser for locally provisioned DNSKEY trust-anchor files. It is not yet a complete network-recursive DNSSEC validator; authenticated negative-proof validation and CLI integration remain in development.

## Getting started

Requires Go 1.23 or later.

```bash
git clone https://github.com/serozr/dnsvet.git
cd dnsvet
go mod download
go test ./...
go run ./cmd/dnsvet help

# Query an A record
go run ./cmd/dnsvet query example.com --server 1.1.1.1 --type A

# Machine-readable JSON output
go run ./cmd/dnsvet query example.com --server 1.1.1.1 --json

# Request DNSSEC records (JSON reports local_validation: not_performed)
go run ./cmd/dnsvet query example.com --server 1.1.1.1 --dnssec --json

# Query the root DNSKEY RRset
go run ./cmd/dnsvet query . --server 1.1.1.1 --type DNSKEY
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## Responsible use

Use dnsvet only on systems and networks you own or are authorized to assess. It is intended for low-impact diagnostics, not denial-of-service, flooding, amplification, or exploitation.

## License

Apache-2.0. See [LICENSE](LICENSE).
