# ADR 0008: Command exit-code contract

- Status: Accepted
- Date: 2026-11-03

## Context

Different CLI commands serve distinct purposes: single queries, batch comparisons, benchmarks, leak detection, and DNSSEC validation. Shell scripts and CI pipelines need consistent, well-defined process exit codes.

## Decision

Standardize exit codes across the CLI:
- **0 (Success)**: Command completed successfully with normal operational outcome (e.g. DNS response received, DNSSEC Secure, no leak indicator found, consistent answers).
- **1 (Operational Failure)**: Network timeout, unreachable resolver, I/O error, or server error (e.g. SERVFAIL or REFUSED).
- **2 (Usage Error)**: Invalid arguments, unknown flag, missing required parameter, or invalid configuration syntax.
- **3 (Security / Diagnostic Finding)**: Authenticated `Insecure` DNSSEC delegation, or diagnostic anomaly / tampering indicator found (inconsistent answers, NXDOMAIN hijacking detected).
- **4 (Indeterminate)**: DNSSEC validation outcome or diagnostic test was inconclusive due to missing proof material or unsupported algorithms.
- **5 (Bogus)**: DNSSEC validation failed due to cryptographic verification failure, signature expiration, digest mismatch, or missing required authentication proof.

## Consequences

- Callers can cleanly distinguish between syntax errors (2), network failures (1), successful execution with benign answer (0), and security/integrity findings (3).
- Consistent behavior across all subcommands.
