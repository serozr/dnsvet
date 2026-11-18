# ADR 0009: Trust anchor sourcing and lifecycle management

- Status: Accepted
- Date: 2026-11-18

## Context

DNSSEC validation requires a cryptographic starting point (trust anchor). The global DNS hierarchy is anchored at the root zone (`.`), currently maintained by IANA. In 2024–2026, IANA is rolling the Root Key Signing Key from KSK-2017 (KeyTag 20326) to KSK-2024 (KeyTag 38696).

Resolvers and tools must manage trust anchors safely across rollovers without hard failing when an old key is retired or a private test environment requires custom trust anchors.

## Decision

1. **Embedded Defaults:**
   `dnsvet` embeds all currently valid IANA root KSKs directly in compiled code (`internal/dnssec/root_anchors.go`). During rollover periods, both old and new keys (e.g. KSK-2017 and KSK-2024) are configured so validation succeeds regardless of which key is active.
   Each embedded key includes its source URL, retrieval date, key tag, algorithm, and expected DS SHA-256 digest.

2. **Automated Sanity Testing:**
   A dedicated unit test (`internal/dnssec/root_anchors_test.go`) validates that the embedded trust anchor set is non-empty, contains valid zone keys, matches expected key tags, and computes exact IANA DS digests.

3. **External Overrides (`--anchor`):**
   Users can supply custom trust anchors via the `--anchor <file>` flag in standard BIND/master-file DNSKEY format. This supports private roots, lab testbeds, and offline environments without modifying code.

4. **Update Cadence:**
   Embedded anchors are reviewed and updated on every major release or whenever IANA publishes a new root anchor in `https://data.iana.org/root-anchors/root-anchors.xml`.

## Consequences

- Out-of-the-box DNSSEC validation works reliably across root key rollovers without requiring network calls to fetch trust anchors on startup.
- Offline tests remain independent of public DNS or remote XML endpoints.
- Private network validation is fully supported via the `--anchor` flag.

