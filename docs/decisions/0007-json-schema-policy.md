# ADR 0007: JSON schema versioning and compatibility policy

- Status: Accepted
- Date: 2026-11-03

## Context

`dnsvet` supports machine-readable output via `--json` across commands (`query`, `discover`, `compare`, `bench`, `validate`, etc.). Automation pipelines and integration tools depend on predictable output structure.

## Decision

Adopt the following JSON schema policy:
1. Every JSON output document top-level object MUST contain `"schema_version": "1"`.
2. Within a major schema version, changes MUST be additive only: new fields may be added, but existing field names and data types MUST NOT be removed or modified.
3. Errors must follow a structured envelope:
   ```json
   {
     "schema_version": "1",
     "error": {
       "code": "machine_readable_snake_case",
       "message": "Human readable explanation"
     }
   }
   ```
4. Field names MUST use `snake_case`. Timestamps and durations should provide both human-readable strings and exact numeric representations (e.g. `elapsed` and `elapsed_ms`).

## Consequences

- Automated consumers can reliably parse output across version upgrades.
- Error codes are machine-matchable without fragile regex parsing on strings.
- Deprecation of any field requires a major schema version bump with advance notice.
