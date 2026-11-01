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

- DNS record queries over UDP and TCP.
- Resolver discovery from operating-system configuration.
- Resolver benchmarking and comparison.
- DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT).
- DNSSEC, DNS leak, NXDOMAIN consistency, and rewriting indicators.
- DNS trace, propagation, and infrastructure diagnostics.
- Terminal, JSON, and eventually HTML reports.

Features will be documented as implemented only after they have working tests.

## Getting started

Requires Go 1.23 or later.

```bash
git clone https://github.com/serozr/dnsvet.git
cd dnsvet
go mod tidy
go test ./...
go run ./cmd/dnsvet help
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## Responsible use

Use dnsvet only on systems and networks you own or are authorized to assess. It is intended for low-impact diagnostics, not denial-of-service, flooding, amplification, or exploitation.

## License

Apache-2.0. See [LICENSE](LICENSE).
