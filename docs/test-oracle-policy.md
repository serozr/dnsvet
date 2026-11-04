# Protocol Test Vector and Deterministic Fixture Policy

## Purpose

This document establishes the test oracle and fixture requirements for `dnsvet`, in accordance with `brain/AGENTS.md` §8.

## The Test-Oracle Rule

Tests that only restate the implementation's internal assumptions prove nothing about protocol compliance. For wire-level DNS parsing, cryptographic verification, and DNSSEC denial proofs, expected test results must be derived from an independent source:

1. **RFC Test Vectors**: Published vectors from authoritative IETF standards (e.g. RFC 4034, RFC 4035, RFC 5155, RFC 6840, RFC 9276), citing the exact RFC number and section.
2. **Independent Tooling Fixtures**: Test zones, records, and signatures generated with independent implementations (e.g. BIND `named-compilezone` / `dnssec-signzone`, `ldns-signzone`, or Unbound), recording the tool version and generation command next to the fixture.
3. **Validator Cross-Checks**: Cross-validation against independent reference validators (`delv`, Unbound `unbound-host -v`, `ldns-verify-zone`).

## Local Determinism

1. **No External Network Dependency**: Unit and integration tests must never query live public resolvers (such as `1.1.1.1` or `8.8.8.8`) or third-party infrastructure.
2. **Local Test Servers**: In-memory DNS servers (`dns.Server` from `miekg/dns`) or loopback listeners (`127.0.0.1` / `::1`) must be used for transport, timeout, truncation, and retry tests.
3. **Explicit Time**: Cryptographic and signature validity tests must use fixed, explicit `time.Time` values rather than `time.Now()`.
4. **Controlled Key Material**: Test key pairs must be deterministically generated or loaded from static fixtures.
