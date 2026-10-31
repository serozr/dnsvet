# ADR 0001: DNS message library

- Status: Accepted
- Date: 2026-11-01

## Context

ResolverGuard needs DNS message construction, parsing, record handling, and protocol support. Reimplementing DNS wire-format behavior would add avoidable complexity and risk.

## Decision

Use `github.com/miekg/dns` as the initial DNS protocol library. Keep its use behind the internal DNS client boundary so application code does not become coupled to library-specific types unnecessarily.

## Consequences

- DNS message handling can rely on a mature implementation.
- The project must track dependency updates and review security advisories.
- Transport and application behavior remain covered by ResolverGuard tests.
