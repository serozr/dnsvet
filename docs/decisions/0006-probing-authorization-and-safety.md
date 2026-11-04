# ADR 0006: Probing authorization, safety limits, and non-goals

- Status: Accepted
- Date: 2026-11-03

## Context

`dnsvet` is a DNS intelligence, diagnostics, and security toolkit. It is intended for administrators, penetration testers on authorized targets, and network engineers. It is not an attack, amplification, or flooding tool.

Uncontrolled concurrency, high query rates, or unauthorized probing could trigger denial-of-service conditions, IP reputation blocks, or firewall alarms.

## Decision

Enforce bounded safety constraints across all active diagnostic capabilities:
1. **Low-impact defaults**: Default query rates must be bounded (maximum 10 queries per second for multi-query operations).
2. **Strict concurrency bounds**: Maximum concurrent queries bounded by default (e.g., 4 concurrent workers).
3. **Bounded timeouts**: Default per-query timeout of 3s; maximum allowed timeout of 60s.
4. **No non-goals**: Zone transfers (`AXFR`/`IXFR`), amplification attacks, broad dictionary enumeration, and covert tunneling probes are strictly disallowed and will not be implemented.
5. **Authorization confirmation**: Commands that send multiple queries to third-party authoritative servers or benchmark endpoints must require explicit CLI invocation with clear user opt-in flags.

## Consequences

- Prevents unintentional denial-of-service or flooding behavior.
- All tests and benchmarks run safely in constrained environments.
- Ensures diagnostic tools operate reliably and ethically.
