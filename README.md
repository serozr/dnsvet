# dnsvet

**dnsvet** is an open-source, cross-platform DNS diagnostics and security toolkit written in Go.

It inspects DNS resolver configuration, query behavior, availability, latency, transport protocols, privacy indicators, and cryptographic DNSSEC validation through an explicit, testable command-line interface.

> **Status:** Alpha. Core query, discovery, benchmarking, comparison, NXDOMAIN hijacking detection, and experimental DNSSEC validation are implemented and tested locally.

---

## Getting Started

### Installation

#### Install via Go
```bash
go install github.com/serozr/dnsvet/cmd/dnsvet@latest
```

#### Build from source
Requires Go 1.26.0 or later:
```bash
git clone https://github.com/serozr/dnsvet.git
cd dnsvet
go build -o dnsvet ./cmd/dnsvet
```

*(Pre-built cross-platform binary releases for Windows, Linux, and macOS will be published on GitHub Releases in v0.1.0).*

---

## Implemented Commands

The commands listed below match `dnsvet help` and are backed by offline/local unit tests.

### 1. `query`
Query DNS records over UDP, TCP, DoT (DNS-over-TLS), or DoH (DNS-over-HTTPS), with optional EDNS0 DNSSEC OK (DO) flag and structured JSON output.

**Example:**
```bash
dnsvet query example.com --server 1.1.1.1 --type A
```

**Sample Output:**
```text
Resolver: 1.1.1.1:53 (transport: udp)
Question: example.com. A
Response: NOERROR (0)
Elapsed: 14.2ms
Answers:
  example.com. 300 IN A 93.184.215.14
```

JSON output is also supported:
```bash
dnsvet query example.com --server 1.1.1.1 --transport tls --json
```

---

### 2. `validate` *(Experimental)*
Cryptographically validate DNSSEC chain of trust from configured trust anchors down to leaf RRsets.

> **Note (Experimental):** The validator walks delegations (DS and DNSKEY) from root trust anchors and verifies signatures (RRSIG) as well as authenticated denial of existence via NSEC and NSEC3 (with RFC 9276 iteration limits). Full recursive arbitrary multi-tier off-path proof assembly and complex CNAME redirection chains are still evolving.

**Example:**
```bash
dnsvet validate example.com --server 1.1.1.1 --type A
```

**Sample Output:**
```text
Validation: SECURE
Domain: example.com. A
Reason: authenticated DS delegation and child DNSKEY signed RRset verified
Zone: example.com.
Trust Anchor: .
Elapsed: 42.1ms
```

---

### 3. `discover`
Discover system-configured DNS resolvers from operating system network settings (e.g., Windows Registry, Unix `/etc/resolv.conf`).

**Example:**
```bash
dnsvet discover
```

**Sample Output:**
```text
Discovered DNS Resolvers:
  Source: windows_registry
  Nameservers (3):
    - 192.168.1.1
    - 8.8.8.8
    - 8.8.4.4
  Search Domains:
    - home
```

---

### 4. `compare`
Compare query answers across multiple DNS resolvers to identify inconsistencies or discrepancies.

**Example:**
```bash
dnsvet compare example.com --servers 1.1.1.1,8.8.8.8,9.9.9.9 --type A
```

**Sample Output:**
```text
Comparing example.com (A) across 3 resolvers:
  [1.1.1.1:53]: NOERROR (12.4ms) -> [93.184.215.14]
  [8.8.8.8:53]: NOERROR (15.1ms) -> [93.184.215.14]
  [9.9.9.9:53]: NOERROR (18.7ms) -> [93.184.215.14]

Consistency: CONSISTENT (all resolvers agree)
```

---

### 5. `bench` *(alias `benchmark`)*
Benchmark resolver round-trip latency and reliability over a sample sequence with controlled query pacing (max 10 QPS).

**Example:**
```bash
dnsvet bench example.com --server 1.1.1.1 --count 10
```

**Sample Output:**
```text
Benchmarking 1.1.1.1:53 with 10 samples for example.com (A):
  Successes: 10/10 (0.0% loss)
  Min:     11.20 ms
  Median:  13.40 ms
  P95:     18.10 ms
  Max:     19.50 ms
  Mean:    14.10 ms ± 2.30 ms
```

---

### 6. `leak` *(alias `hijack`)*
Detect NXDOMAIN hijacking and wildcard DNS synthesis by querying reserved non-existent domain names (RFC 6761).

> **Scope Note:** This command tests for local NXDOMAIN rewriting, interception, and search-assistant redirection. True upstream DNS query leak detection is planned for a later phase.

**Example:**
```bash
dnsvet leak --server 1.1.1.1
```

**Sample Output:**
```text
Testing 1.1.1.1:53 for DNS hijacking & NXDOMAIN rewriting:
  Result: NO REWRITING DETECTED (compliant NXDOMAIN responses for RFC 6761 names)
  Confidence: high
  Tested Names: [dnsvet-nxdomain-test-...example.invalid]
  Limitations: Detects NXDOMAIN redirection and synthesis only; does not observe query leakage outside local network path.
```

---

### 7. `version`
Show dnsvet version, git commit, build date, Go compiler version, and platform target.

**Example:**
```bash
dnsvet version
```

**Sample Output:**
```text
dnsvet dev
Commit: unknown
Built: unknown
Go: go1.27.3
Platform: windows/amd64
```

---

### 8. `help`
Display command list and CLI options.

**Example:**
```bash
dnsvet help
```

---

## Planned Capabilities

The following features are designed and scheduled in the [Development Plan](brain/plan.md):

- **`dnsvet check` (Phase 4):** Comprehensive one-shot diagnostic verdict evaluating resolver reachability, transport security (TCP/DoT/DoH), DNSSEC validation enforcement, latency health, and tampering indicators against explicit rule IDs.
- **Upstream DNS Leak Detection (Phase 5):** Out-of-band identification of actual upstream resolving infrastructure.
- **Iterative DNS Trace (`trace`):** Root-to-leaf iteration displaying per-hop authority delegations and delegation latency.
- **Authoritative Propagation Check:** Compare record propagation directly across zone NS delegations.
- **Standalone HTML Diagnostic Reports:** Export single-file, zero-dependency visual reports from JSON evaluation models.
- **Rule & Target Configuration (`--config`):** Custom thresholds and baseline resolver pools.

---

## Documentation

- [CLI Command & Flag Reference](docs/commands.md)
- [Exit Code Contract](docs/exit-codes.md)
- [Architecture & Design Decisions (ADRs)](docs/decisions/)
- [Test Oracle & Isolation Policy](docs/test-oracle-policy.md)

---

## Responsible Use

Use dnsvet only on systems, resolvers, and networks you own or are authorized to assess. It is strictly designed for diagnostic analysis and network hygiene, adhering to safe query limits and bounded timeouts. It does not provide any denial-of-service, flooding, amplification, or exploitation capabilities.

---

## License

Apache-2.0. See [LICENSE](LICENSE).
