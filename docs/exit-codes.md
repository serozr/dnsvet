# Exit Code Contract

dnsvet process exit codes provide deterministic signals for shell scripts, automated security audits, and CI/CD pipelines.

---

## Global Exit Codes

| Exit Code | Classification | Meaning |
|:---:|---|---|
| **0** | **Success / Clean** | Command completed successfully with normal operational outcome and no security/integrity findings. |
| **1** | **Operational Failure** | Network timeout, unreachable resolver, socket error, or server query error. |
| **2** | **Usage Error** | Invalid command-line arguments, unknown flags, unsupported types/transports, or syntax errors. |
| **3** | **Diagnostic Finding** | Diagnostic check detected an anomaly or tampering indicator. |
| **4** | **Indeterminate** | Evaluation was inconclusive due to missing proof material or unsupported algorithms. |

---

## Command-Specific Behavior

### `query`
- **0**: Response successfully received from resolver.
- **1**: Resolver network timeout, connection refused, or invalid server address.
- **2**: Argument syntax error, unsupported record type, or invalid duration.

### `validate` *(Current Contract & Phase 2 Roadmap)*
Current behavior:
- **0**: DNSSEC validation status is **Secure** (cryptographic chain of trust verified to trust anchor).
- **1**: Network or operational error querying DS/DNSKEY records during chain traversal.
- **2**: Missing domain argument, unparseable trust anchor file, or invalid options.
- **3**: Validation status is **Insecure** (authenticated unsigned delegation) or **Bogus** (validation failed / forged).
- **4**: Validation status is **Indeterminate** (unsupported algorithm, missing signatures, or inconclusive proof).

*Planned in Phase 2:*
- **3**: **Insecure** (zone is legitimately unsigned, proof of no DS verified).
- **5**: **Bogus** (cryptographic signature verification failed, digest mismatch, or unverifiable delegation).

### `compare`
- **0**: All queried resolvers returned **Consistent** answers.
- **1**: Failed to query one or more target resolvers due to operational errors.
- **2**: Invalid arguments or invalid resolver address list.
- **3**: **Inconsistent** answers observed across resolvers (e.g., answer RRset mismatch, differing RCODEs).

### `bench`
- **0**: Benchmark completed successfully with recorded sample stats.
- **1**: Target resolver unreachable or total query failure.
- **2**: Invalid arguments, invalid sample count (`--count` outside 1–100), or invalid timeout.

### `leak`
- **0**: No NXDOMAIN hijacking or rewriting detected (RFC 6761 compliant).
- **1**: Operational failure contacting target resolver.
- **2**: Invalid arguments or options.
- **3**: **Hijacking / Rewriting Detected** (resolver synthesized positive records for non-existent domains).

### `discover`
- **0**: System resolvers discovered successfully.
- **1**: Operational error reading system resolver configuration.
- **2**: Invalid arguments.

### `version` & `help`
- **0**: Version or usage information displayed.
- **2**: Unknown flag or subcommand.
