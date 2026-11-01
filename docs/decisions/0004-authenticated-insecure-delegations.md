# ADR 0004: Authenticated insecure delegation classification

- Status: Proposed
- Date: 2026-11-01

## Context

ResolverGuard can currently authenticate a supplied sequence of signed DS and DNSKEY RRsets. It does not yet validate NSEC or NSEC3 denial proofs, and `ValidateChain` deliberately rejects incomplete delegation material.

A missing DS RRset is not, by itself, proof that a child zone is insecure. The response may be incomplete, truncated, stale, forged, or obtained from an unauthenticated source. Treating absence as insecurity would create a downgrade path and could incorrectly label a bogus or indeterminate chain as insecure.

The DNSSEC result model already distinguishes Secure, Insecure, Bogus, and Indeterminate. The implementation needs an evidence-based rule for the Insecure outcome.

## Decision

ResolverGuard MUST classify a delegation as **Insecure** only when it has authenticated evidence from the parent zone that no DS RRset exists at the delegation point.

The evidence must be a valid denial proof (NSEC or NSEC3) whose signatures validate with the already-authenticated parent-zone DNSKEY set and whose semantics prove absence of DS for the exact delegation owner.

The following observations MUST NOT independently produce Insecure:

- An empty DS answer without a validated denial proof.
- A timeout, SERVFAIL, REFUSED, or transport error.
- Missing DS records in a caller-supplied collection.
- An unsigned child DNSKEY RRset.
- An unsupported digest or signature algorithm.
- A failed or unverifiable RRSIG.
- A resolver's AD bit or other resolver-reported metadata.

If proof material is missing or cannot be evaluated, the result is **Indeterminate**. If proof material is present but cryptographically invalid or semantically contradictory, the result is **Bogus**. A valid authenticated DS path and valid child DNSKEY RRset remain **Secure**.

## NSEC requirements

An NSEC proof implementation must:

1. Validate the NSEC RRset RRSIG using authenticated parent-zone keys.
2. Validate canonical DNS name ordering and the NSEC owner-to-next-name interval.
3. Confirm that the NSEC bitmap at the delegation owner omits DS when proving an insecure delegation.
4. Reject malformed owner names, next-domain names, bitmaps, and inconsistent proof sets.
5. Keep ordinary NXDOMAIN/NODATA proof validation distinct from the specific DS-absence-at-delegation decision.

An NSEC record that merely covers a name is not sufficient unless the proof semantics establish the required denial for the queried delegation point.

## NSEC3 requirements

An NSEC3 proof implementation must:

1. Validate the NSEC3 RRset RRSIG using authenticated parent-zone keys.
2. Validate hash algorithm support, iterations, salt, owner hash, next hash, and type bitmap.
3. Apply the NSEC3 proof rules for the exact delegation owner and DS absence.
4. Handle Opt-Out explicitly. An Opt-Out covering proof may establish an insecure delegation only when all applicable NSEC3 semantics and delegation conditions are satisfied; it must not be treated as a generic denial proof.
5. Reject inconsistent parameters or proof sets rather than guessing.

NSEC3 Opt-Out, closest-encloser, next-closer, and wildcard proof handling must be implemented from the applicable DNSSEC specifications and covered by deterministic test vectors before being used for general negative-answer classification.

## API and implementation sequence

The validator should keep cryptographic verification and proof interpretation separate from network transport.

1. Introduce explicit evidence types for authenticated NSEC and NSEC3 material. Do not represent absence as an empty RRset alone.
2. Add pure validation functions that accept the proof material, authenticated parent keys, delegation owner, and validation time.
3. Return a typed proof outcome that distinguishes proven DS absence, not-proven, unsupported, and invalid evidence.
4. Integrate the proof outcome into delegation-chain classification:
   - authenticated DS + valid child DNSKEY chain: Secure;
   - authenticated DS absence at the delegation: Insecure;
   - invalid signature or contradictory denial evidence: Bogus;
   - missing or unsupported evidence: Indeterminate.
5. Add deterministic tests using locally generated signed zones and published protocol test vectors. No unit test may depend on public DNS.
6. Only after the proof primitives are complete should the CLI expose the Insecure result.

The implementation must remain bounded: cap proof RR counts and NSEC3 iteration work, avoid broad zone enumeration, and do not perform zone transfers.

## Consequences

- Insecure is an evidence-backed result rather than a fallback for missing DS data.
- The validator may return Indeterminate more often until authenticated denial support is complete. This is intentional and safer than a false classification.
- NSEC and NSEC3 can be implemented and tested independently before they are connected to chain walking or CLI output.
- Full DNSSEC validation remains incomplete until authenticated negative proofs and end-to-end result classification are implemented.
