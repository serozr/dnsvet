# Architecture Decision Records (ADRs)

This directory records architectural and design decisions for `dnsvet`.
Each decision follows the template defined in [`template.md`](template.md).

## Index

| ADR | Title | Status | Date |
|---|---|---|---|
| [0001](0001-dns-library.md) | DNS message library (`miekg/dns`) | Accepted | 2026-11-01 |
| [0002](0002-cross-platform.md) | Cross-platform implementation | Accepted | 2026-11-01 |
| [0003](0003-dnssec-validation.md) | DNSSEC validation architecture | Accepted | 2026-11-01 |
| [0004](0004-authenticated-insecure-delegations.md) | Authenticated insecure delegation classification | Accepted | 2026-11-01 |
| [0005](0005-windows-resolver-discovery.md) | Windows resolver discovery via IP Helper API | Accepted | 2026-11-03 |
| [0006](0006-probing-authorization-and-safety.md) | Probing authorization, safety limits, and non-goals | Accepted | 2026-11-03 |
| [0007](0007-json-schema-policy.md) | JSON schema versioning and compatibility policy | Accepted | 2026-11-03 |
| [0008](0008-exit-code-contract.md) | Command exit-code contract | Accepted | 2026-11-03 |
