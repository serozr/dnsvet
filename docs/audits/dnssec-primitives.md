# DNSSEC primitives audit

## Scope and method

This audit covers the current pure validation primitives in
[`internal/dnssec`](../../internal/dnssec), their unit tests, and the DNSSEC
correctness requirements in [`brain/AGENTS.md`](../../brain/AGENTS.md).
It is an audit inventory, not an implementation of the missing validator.
The review deliberately treats the current APIs as supplied-material
validators; they do not fetch records or establish trust from an untrusted
source.

The current tests are deterministic and use locally generated Ed25519 keys.
They do not yet use published RFC vectors or an independent DNSSEC
implementation as an oracle.

## What is already covered

- RRset grouping and RRSIG selection reject nil records and preserve
  owner/class/type relationships.
- RRSIG verification checks the covered RRset, signer name, key tag,
  algorithm, validity interval, and cryptographic signature.
- DS-to-DNSKEY matching checks owner, class, protocol, key identity, digest
  type, and digest value.
- Trust-anchor files have size, line, key-count, zone, duplicate, protocol,
  and zone-flag limits.
- Supplied DS/DNSKEY chains have a maximum delegation depth.
- NSEC primitives distinguish `proven`, `not_proven`, `unsupported`, and
  `invalid`, and keep delegation DS absence separate from ordinary NODATA
  handling.

These properties are useful safeguards, but they do not make the package a
complete DNSSEC validator.

## Findings

| ID | Priority | Area | Evidence | Risk or gap | Required follow-up |
|---|---|---|---|---|---|
| DNSSEC-001 | High | Trust-anchor key usability | [`trust_anchor.go:27`](../../internal/dnssec/trust_anchor.go) validates protocol 3, but the programmatic `TrustAnchor` path does not require the DNSKEY Zone flag. [`trust_anchor_file.go:58`](../../internal/dnssec/trust_anchor_file.go) does require it for parsed files. | A caller can configure a key that is not marked as a zone key and still use it as a trust anchor. This creates inconsistent policy between file-provisioned and programmatically provisioned anchors. | Add a regression test for a configured anchor without the Zone flag, then enforce the same key usability rule in `ValidateTrustAnchorDNSKEYSet`. Decide and document whether SEP is required or merely permitted. |
| DNSSEC-002 | High | Child DNSKEY usability | [`child_dnskey.go:44`](../../internal/dnssec/child_dnskey.go) returns every protocol-3 DNSKEY in the signed RRset. It does not require the Zone flag for returned signing keys. | A non-zone key can be carried forward as an authenticated usable key. The RRset signature is valid, but the resulting key set may be unsuitable for zone authentication. | Add tests for protocol-3 keys with and without the Zone flag. Define the accepted DNSKEY flag policy before changing the implementation. |
| DNSSEC-003 | Medium | Validation input bounds | [`verify.go:24`](../../internal/dnssec/verify.go) iterates over caller-supplied records, signatures, and keys without package-level count or size limits. [`chain.go:10`](../../internal/dnssec/chain.go) bounds only delegation depth, while trust-anchor parsing has separate file limits. | A future network or message adapter can pass very large collections and cause excessive CPU or memory use. The primitive is safe only when every caller independently bounds DNS responses. | Define named limits for RRset records, signatures, keys, and total validation work. Enforce them at the boundary that converts DNS messages into validation inputs, and add boundary tests. |
| DNSSEC-004 | Medium | RRset canonical integrity | [`types.go:38`](../../internal/dnssec/types.go) groups records but does not reject duplicate records. `VerifyRRset` also accepts the supplied ordering and relies on `miekg/dns` during signature verification. | Duplicate or non-canonical input can be authenticated inconsistently across adapters and makes evidence accounting ambiguous. The current tests cover grouping, but not duplicate or canonical-wire equivalence cases. | Add independent duplicate and canonicalization tests. Decide whether duplicate rejection belongs in grouping or in the validation boundary, then document the invariant. |
| DNSSEC-005 | Medium | DS/RRset metadata validation | [`ds.go:16`](../../internal/dnssec/ds.go) checks owner and class but assumes the caller has supplied a correctly typed `*dns.DS`. Similar typed-record assumptions exist in delegation and NSEC paths. | A future generic message adapter could pass malformed or contradictory metadata into a primitive and receive a misleading validation result. | Add explicit type/header invariant tests at every public primitive boundary, and centralize the checks where practical. |
| DNSSEC-006 | Medium | Delegation boundary coverage | [`delegation.go:133`](../../internal/dnssec/delegation.go) permits any strict descendant through `isChildZone`. This may be valid for an explicitly supplied direct zone cut, but the API does not express or verify whether intermediate zones were skipped. | A chain caller can accidentally present a non-contiguous sequence and obtain a result that is cryptographically coherent but not a complete delegation path. | Keep the flexible name relationship only if the eventual chain model proves each zone cut. Add tests for direct, multi-label, skipped, and out-of-zone delegation sequences before recursive fetching is introduced. |
| DNSSEC-007 | Medium | NSEC proof scope | [`nsec_interval_proof.go:17`](../../internal/dnssec/nsec_interval_proof.go), [`nsec_nodata_proof.go:20`](../../internal/dnssec/nsec_nodata_proof.go), and [`nsec_delegation.go:35`](../../internal/dnssec/nsec_delegation.go) intentionally validate narrow single-record cases. They do not construct complete NXDOMAIN, wildcard, referral, or response-code proofs. | A caller must not map these primitive results directly to Secure or Insecure for a DNS response. Doing so would permit incomplete denial evidence to be treated as a complete proof. | Preserve the narrow APIs, add typed proof-input/result structures for complete proofs, and keep integration blocked until closest-encloser, next-closer, wildcard, and response consistency rules are implemented. |
| DNSSEC-008 | Medium | Independent test oracle | Existing tests generate keys and signatures in-process, for example [`verify_test.go:27`](../../internal/dnssec/verify_test.go), and assert results using the same library family used by production verification. No test cites an RFC vector or cross-checks `delv`, Unbound, or ldns. | A shared implementation assumption can make both fixture generation and verification agree on incorrect behavior. This is especially important for canonical ordering, wildcard labels, DS digest preference, and denial proofs. | Add RFC-referenced vectors and independently generated signed-zone fixtures. Record the generator and validator versions/commands next to each fixture, as required by the repository test-oracle rule. |
| DNSSEC-009 | Low | Error/result taxonomy | The primitives return ordinary Go errors for many conditions and typed NSEC statuses for others. [`types.go:8`](../../internal/dnssec/types.go) defines the eventual four validation statuses, but no orchestrator maps primitive errors to them yet. | Future CLI integration could accidentally classify unsupported, incomplete, and cryptographically invalid evidence the same way. | Define the mapping at the validation-orchestrator boundary: invalid authenticated material is Bogus, missing/unsupported evidence is Indeterminate, and only a complete authenticated path is Secure. |

## Explicitly out of scope today

The following are known missing capabilities rather than defects in the
narrow primitives:

- Recursive network chain construction and resolver integration.
- General authenticated NXDOMAIN, NODATA, and wildcard proofs.
- NSEC3 hashing, interval logic, Opt-Out semantics, and iteration limits.
- DNSSEC validation mode in the CLI and JSON result contract.
- Automatic trust-anchor updates.

Until these are implemented and independently tested, the package must not
claim end-to-end Secure, Insecure, Bogus, or Indeterminate results for live
DNS answers.

## Recommended implementation order

1. Resolve DNSSEC-001 and DNSSEC-002 with regression tests and an explicit
   DNSKEY flag policy.
2. Add bounded validation-input limits and malformed/duplicate RRset tests.
3. Add RFC and independent-tool fixtures for the existing RRSIG, DS, trust
   anchor, and NSEC primitives.
4. Implement complete NSEC proof semantics before starting NSEC3 or recursive
   network fetching.
5. Add the validation orchestrator only after the proof outcomes and status
   mapping are explicit.
