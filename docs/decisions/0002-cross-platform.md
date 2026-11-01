# ADR 0002: Cross-platform implementation

- Status: Accepted
- Date: 2026-11-01

## Context

dnsvet targets Windows, Linux, and macOS. Platform-specific resolver discovery may be required, but the DNS query engine should remain portable.

## Decision

Keep the core query and analysis logic platform-independent. Isolate operating-system-specific resolver discovery behind small platform-specific implementations.

## Consequences

- Core DNS tests can run consistently across operating systems.
- Platform-specific discovery requires dedicated tests and clear fallback behavior.
- Normal DNS queries must not require administrator or root privileges.
