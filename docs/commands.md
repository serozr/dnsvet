# CLI Command & Flag Reference

Complete reference for all `dnsvet` subcommands, command-line arguments, supported transports, record types, defaults, and timeouts.

---

## Global Invariants

- **Safe Defaults:** Every command enforces bounded timeouts, query pacing, and bounded retry counts.
- **Output Formats:** By default, commands emit human-readable plain text without hard terminal color dependencies (respects `NO_COLOR`). All query and diagnostic commands support `--json` emitting versioned JSON (`schema_version: "1"`).
- **Resolver Formats:** IPv4 (`1.1.1.1`), IPv6 (`[2606:4700:4700::1111]`), hostnames, and custom ports (`1.1.1.1:5353`) are normalized automatically.

---

## 1. `query`

Query DNS records over standard or encrypted transports.

### Syntax
```bash
dnsvet query <domain> [options]
```

### Options

| Flag | Short | Default | Description |
|---|---|---|---|
| `--server <address>` | `-s` | `1.1.1.1` | Target resolver address. |
| `--type <record>` | `-t` | `A` | DNS record type to query. |
| `--transport <proto>` | | `udp` | Transport: `udp`, `tcp`, `tls` (or `dot`), `https` (or `doh`). |
| `--timeout <duration>` | | `3s` | Query timeout (e.g. `500ms`, `2s`, max `60s`). |
| `--dnssec` | | `false` | Set EDNS0 DO (DNSSEC OK) bit to request DNSSEC RRs and inspect AD bit. |
| `--json` | | `false` | Output structured JSON (`schema_version: "1"`). |
| `--help` | `-h` | | Show usage information. |

### Supported Record Types
`A`, `AAAA`, `CNAME`, `MX`, `NS`, `PTR`, `SOA`, `SRV`, `TXT`, `CAA`, `DS`, `DNSKEY`, `RRSIG`, `NSEC`, `NSEC3`.
*(Zone transfer types such as AXFR/IXFR are rejected).*

### Transport Protocols
- `udp`: Standard DNS over UDP with automatic retry over TCP on truncation (TC bit).
- `tcp`: Explicit DNS over TCP.
- `tls` / `dot`: DNS over TLS (RFC 7858), default port 853.
- `https` / `doh`: DNS over HTTPS (RFC 8484) wireformat, default port 443.

---

## 2. `validate` *(Experimental)*

Cryptographically validate DNSSEC chain of trust from configured trust anchors down to target record sets.

### Syntax
```bash
dnsvet validate <domain> [options]
```

### Options

| Flag | Short | Default | Description |
|---|---|---|---|
| `--server <address>` | `-s` | `1.1.1.1` | Resolver used to walk intermediate DS and DNSKEY records. |
| `--type <record>` | `-t` | `A` | Record type to validate. |
| `--anchor <file>` | | *(embedded root KSK)* | Path to a master-file format file containing trusted DNSKEY records. |
| `--timeout <duration>` | | `5s` | Query timeout per chain step (max `60s`). |
| `--json` | | `false` | Output structured JSON (`schema_version: "1"`). |
| `--help` | `-h` | | Show usage information. |

### Validation Capabilities & Scope
- **Chain Walking:** Walks parent-to-child delegations starting from configured trust anchors (defaulting to the root zone `.`).
- **Signature Verification:** Verifies RRSIG validity intervals and cryptographic signatures over RRsets.
- **Denial of Existence:** Validates authenticated non-existence and NODATA proofs via NSEC and NSEC3 (with RFC 9276 iteration limits and Opt-Out handling).
- **Delegation Security:** Detects provably authenticated insecure delegations.

---

## 3. `discover`

Discover system-configured DNS resolvers from the operating system configuration.

### Syntax
```bash
dnsvet discover [options]
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--json` | `false` | Output structured JSON (`schema_version: "1"`). |
| `--help` | | Show usage information. |

### Platform Implementation
- **Windows:** Queries active network adapter registry keys under `System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`.
- **Unix / Linux / macOS:** Parses `/etc/resolv.conf` for `nameserver` and `search`/`domain` directives.

---

## 4. `compare`

Compare answers for a domain and record type across multiple DNS resolvers.

### Syntax
```bash
dnsvet compare <domain> [options]
```

### Options

| Flag | Short | Default | Description |
|---|---|---|---|
| `--servers <list>` | `-s` | *(OS discovered, or 1.1.1.1,8.8.8.8,9.9.9.9)* | Comma-separated list of resolver addresses. |
| `--type <record>` | `-t` | `A` | DNS record type to query across resolvers. |
| `--timeout <duration>` | | `3s` | Timeout per resolver query. |
| `--json` | | `false` | Output structured JSON (`schema_version: "1"`). |
| `--help` | `-h` | | Show usage information. |

---

## 5. `bench` *(alias `benchmark`)*

Benchmark resolver latency, jitter, and packet loss over a sequential sample run.

### Syntax
```bash
dnsvet bench <domain> [options]
```

### Options

| Flag | Short | Default | Description |
|---|---|---|---|
| `--server <address>` | `-s` | `1.1.1.1` | Resolver address to benchmark. |
| `--count <number>` | `-c` | `10` | Number of sequential queries (min 1, max 100). |
| `--type <record>` | `-t` | `A` | DNS record type to query. |
| `--timeout <duration>` | | `3s` | Per-query timeout. |
| `--json` | | `false` | Output structured JSON (`schema_version: "1"`). |
| `--help` | `-h` | | Show usage information. |

### Pacing & Safety
To prevent accidental traffic bursts or flood triggers against recursive resolvers, sequential queries are paced with a minimum 100ms pause, capping query rate at ≤ 10 queries per second (QPS).

---

## 6. `leak` *(alias `hijack`)*

Detect NXDOMAIN hijacking, ISP search-redirection, and DNS tampering.

### Syntax
```bash
dnsvet leak [options]
```

### Options

| Flag | Short | Default | Description |
|---|---|---|---|
| `--server <address>` | `-s` | `1.1.1.1` | Resolver address to test. |
| `--timeout <duration>` | | `3s` | Timeout per test probe. |
| `--json` | | `false` | Output structured JSON (`schema_version: "1"`). |
| `--help` | `-h` | | Show usage information. |

### Detection Mechanism
Queries unique randomized domain names ending in RFC 6761 reserved special-use TLDs (`.invalid`). A standard resolver must return `NXDOMAIN` (RCODE 3). Resolvers returning `NOERROR` with synthesized `A` or `CNAME` records are flagged as tampering/rewriting.

---

## 7. `version`

Display CLI version, Git commit SHA, build timestamp, Go compiler version, and target OS/architecture.

### Syntax
```bash
dnsvet version
```

---

## 8. `help`

Display the general CLI help screen and list of available subcommands.

### Syntax
```bash
dnsvet help
```
