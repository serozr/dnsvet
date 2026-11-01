# ADR 0003: DNSSEC validation architecture

- Status: Accepted
- Date: 2026-11-01

## Context

dnsvet can query DNSSEC-related record types, but retrieving DNSKEY, DS, RRSIG, NSEC, or NSEC3 records is not DNSSEC validation. A recursive resolver's AD (Authenticated Data) bit is also not proof that dnsvet independently validated the answer.

DNSSEC validation must be explicit, explainable, bounded, and fail closed. An incorrect "secure" result is worse than an unavailable result.

## Decision

Implement DNSSEC as a separate internal package, `internal/dnssec`, with no CLI or transport dependencies. Keep DNS message transport in `internal/dnsclient`.

The validator will expose four distinct outcomes:

- **Secure**: the RRset signature and the chain to a configured trust anchor were successfully validated.
- **Insecure**: an authenticated delegation proves that the queried namespace is not signed.
- **Bogus**: validation was required but a signature, key, delegation, or denial proof is invalid or inconsistent.
- **Indeterminate**: the validator lacks enough trusted information to decide, for example because of timeout, unsupported algorithm, missing data, or unavailable trust anchor.

Only **Secure** may be described as cryptographically validated. AD-bit observations, if later displayed, must be reported separately as resolver-reported metadata.

## Validation model

Validation is layered and must not be collapsed into one signature check:

1. **RRset validation**: group records by owner name, class, and type; locate candidate RRSIG records; check signer name, covered type, key tag, algorithm, inception/expiration, and cryptographic signature.
2. **DNSKEY trust**: match a DNSKEY to an authenticated DS using key tag, algorithm, and digest type; verify the DNSKEY RRset with an appropriate zone key.
3. **Delegation chain**: walk from the queried zone toward a configured root trust anchor, validating each parent DS RRset and child DNSKEY RRset.
4. **Negative answers**: validate NSEC/NSEC3 denial proofs before treating authenticated NXDOMAIN or NODATA as secure.
5. **Result classification**: distinguish authenticated insecurity from validation failure and from missing information.

The initial trust-anchor policy will be deterministic and local. Trust anchors must be explicitly versioned and testable. Automatic trust-anchor updates (RFC 5011) are out of the first implementation scope.

## Implementation sequence

- **Phase A — primitives**: immutable validation result types, RRset grouping, DNSKEY/DS matching, signature time checks, and cryptographic verification wrappers. No network chain walking.
- **Phase B — trust chain**: root trust anchor loading and bounded DS/DNSKEY chain construction.
- **Phase C — negative proofs**: NSEC and NSEC3 proof validation.
- **Phase D — CLI integration**: explicit DNSSEC validation mode and structured output. Never silently equate the resolver AD bit with local validation.

Each phase must have deterministic unit tests using locally generated keys and signed test zones. Tests must cover valid signatures, modified RRsets, wrong keys, expired and not-yet-valid signatures, DS digest mismatch, missing signatures, unsupported algorithms, and context cancellation. No unit test may depend on public DNS.

## Safety and correctness constraints

- Never return **Secure** without a complete authenticated path to a configured trust anchor.
- Never downgrade **Bogus** to **Insecure** because validation failed.
- Unsupported algorithms and incomplete chains are **Indeterminate**, not **Secure**.
- Bound network lookups, recursion depth, response sizes, and per-query time.
- Do not perform zone transfers or broad discovery as part of validation.
- Keep trust-anchor material and validation policy separate from ordinary resolver configuration.
- Preserve the distinction between records requested with the EDNS DO bit and records that have actually been validated.

## Consequences

- DNSSEC logic can be tested independently of UDP/TCP transport and CLI presentation.
- The implementation is more work than trusting the resolver AD bit, but its results are materially more defensible.
- Full DNSSEC support is not complete until chain construction and authenticated denial proofs are implemented and tested.

## Implementation status

As of v0.1.5, the repository contains tested primitives for RRset grouping, DNSKEY-to-DS matching, RRset signature verification, pinned trust-anchor DNSKEY-set validation, and parent-authenticated DS delegation validation.

DS matching follows RFC 4509 section 3: when an authenticated DS RRset contains SHA-256 DS records, SHA-1 DS records are ignored for key matching. SHA-1 remains supported when no SHA-256 DS record is present. The complete signed DS RRset is verified before this preference is applied. This is the RFC's SHOULD-level preference, not a blanket rejection of SHA-1-only delegations.

These primitives do not yet constitute a complete DNSSEC validator. Recursive chain construction, child DNSKEY RRset validation as a connected workflow, authenticated NSEC/NSEC3 denial proofs, and CLI validation output remain outstanding.
