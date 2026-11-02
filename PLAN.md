# dnsvet — Development Roadmap & Agent Rules

> Last reviewed: 2026-11-03  
> Repository: https://github.com/serozr/dnsvet  
> Default branch: `main`  
> Current baseline: `1d08c28b73dc4bd125284b7a726187ed56ae6e1e`  
> Status: Early development — DNS query foundation and DNSSEC validation primitives exist; this is not yet a complete DNS diagnostics product or a complete recursive DNSSEC validator.

---

## 1. Product Direction

dnsvet is a cross-platform, local-first DNS diagnostics and security intelligence CLI written in Go.

Its purpose is to help users understand DNS behavior, resolver reliability, privacy characteristics, DNSSEC correctness, and infrastructure health through explicit, reproducible, explainable checks.

### Product principles

- No AI dependency. Analysis must be deterministic, explainable, and testable.
- Cross-platform: Windows, Linux, and macOS.
- Safe by default: low query rates, bounded timeouts, bounded concurrency, bounded response/proof sizes.
- Correctness before feature count. Never claim a security property that has not been independently verified.
- Offline/deterministic tests wherever possible. Unit tests must not depend on public DNS.
- Stable CLI behavior and versioned machine-readable JSON.
- Keep transport, protocol validation, diagnostics, presentation, and OS-specific discovery separated.

### Non-goals

- DNS flooding, amplification, denial-of-service, exploitation, stealth, or unauthorized reconnaissance.
- Zone transfers or broad zone enumeration.
- Treating resolver-provided AD as local cryptographic validation.
- AI-generated risk verdicts.
- Claiming full DNSSEC support while proof construction or trust-chain validation is incomplete.

## 2. Current Repository Baseline

### Implemented foundation

- Go CLI at `cmd/dnsvet`.
- DNS query transport in `internal/dnsclient`.
- UDP queries and TCP fallback for truncated UDP responses.
- Query validation (response flag, opcode, echoed question).
- Resolver and DNS name normalization, including IDN handling.
- Query types include common records and DNSSEC-related records.
- JSON output schema v1, elapsed timing, structured JSON errors.
- DNSSEC package in `internal/dnssec`:
  - RRset grouping and RRSIG selection.
  - RRSIG time and cryptographic verification against supplied keys.
  - DS-to-DNSKEY matching.
  - Trust anchor parsing and pinned DNSKEY-set validation.
  - Parent-authenticated DS and supplied delegation-chain validation.
  - Authenticated NSEC interval primitive.
  - Narrow exact-owner NODATA and delegation DS-absence NSEC primitives.
- CI workflow: `.github/workflows/ci.yml`
  - Ubuntu, Windows, macOS test/vet/build.
  - `go mod tidy -diff`, `go mod verify`, gofmt.
  - Ubuntu race detector and govulncheck.

### Explicitly incomplete

- No complete network-driven recursive DNSSEC validator.
- No complete general-purpose NXDOMAIN/NODATA/wildcard proof validation.
- No NSEC3 validation.
- No connected authenticated insecure-delegation classification workflow.
- No DNSSEC validation mode integrated into the CLI.
- No OS resolver discovery.
- No DoH or DoT transport.
- No resolver benchmarking/comparison.
- No DNS leak, rewrite, or NXDOMAIN consistency diagnostics.
- No trace/propagation/infrastructure diagnostics.
- No HTML report or release packaging workflow.

### Repository consistency issue

The README currently requires Go 1.27.3 (from `go.mod`), but CONTRIBUTING.md still says Go 1.23 or later. Resolve this inconsistency before calling the developer documentation complete. Keep `go.mod` as the single source of truth for the Go version.

### Latest verified CI baseline

The latest commit `1d08c28` had a successful CI run. An immediately preceding run failed, followed by a successful run on the final commit. Always inspect the latest run for the exact head SHA; do not infer current CI health from an older green run.

---

## 3. Roadmap — Ordered Phases

Do not skip phases just to add visible features. Finish and verify each phase before moving on. The checkboxes are the source of truth; only mark an item complete after implementation, tests, and verification.

### Phase 0 — Baseline, consistency, and engineering hygiene

- [ ] Verify `go test ./...`, `go test -race ./...`, `go vet ./...`, `go build ./...`, `go mod tidy -diff`, and `go mod verify` locally.
- [ ] Confirm latest GitHub Actions run on the current HEAD SHA.
- [ ] Fix Go version mismatch between README and CONTRIBUTING.
- [ ] Review CLI help, exit codes, JSON success/error behavior, and schema version stability.
- [ ] Audit error wrapping and ensure errors do not leak secrets or produce misleading classifications.
- [ ] Establish a documented policy for protocol test vectors and deterministic fixtures.
- [ ] Do not refactor unrelated code during this phase.

**Exit criteria:** clean local checks, latest CI green, docs agree on Go version and current feature scope.

### Phase 1 — DNSSEC primitive audit and proof correctness

This is the immediate priority. Review existing code against the relevant DNSSEC RFCs and independent test vectors before extending it.

- [ ] Audit RRset grouping: canonical owner handling, class/type consistency, duplicate records, RRSIG association.
- [ ] Audit RRSIG verification: signer-name relationship, key tag, algorithm, type-covered, validity boundaries, malformed signatures, wildcard label handling, and supported algorithms.
- [ ] Audit DS/DNSKEY matching: digest handling, key identity, protocol/zone flags, unsupported digest behavior, and mixed digest sets.
- [ ] Audit trust-anchor parser limits, malformed multiline records, duplicate keys, zone constraints, and trusted provisioning assumptions.
- [ ] Audit delegation validation: parent/child relationships, class, owner consistency, key usability, and chain boundary conditions.
- [ ] Audit NSEC canonical wire ordering, open interval endpoints, wrap-around, one-record zones, zone boundaries, and delegation cuts.
- [ ] Audit exact-owner NODATA logic, CNAME bitmap behavior, delegation handling, and unsupported query types.
- [ ] Audit DS-absence-at-delegation NSEC proof separately from general NSEC interval/NODATA proofs.
- [ ] Add tests for every discovered gap before changing implementation.
- [ ] Prefer RFC test vectors and independently verified edge cases over tests that merely restate implementation assumptions.

**Exit criteria:** primitives have explicit scope, robust edge-case tests, no known incorrect Secure/Insecure classification, and documented limitations.

### Phase 2 — Complete authenticated denial proofs (NSEC)

- [ ] Define explicit proof input and result types; do not conflate one NSEC interval check with a complete DNS denial proof.
- [ ] Implement general NXDOMAIN proof semantics (closest encloser, next closer, wildcard denial) using authenticated RRsets.
- [ ] Implement general NODATA proof semantics, including exact owner and wildcard-derived cases where applicable.
- [ ] Keep delegation-point DS absence a distinct proof path.
- [ ] Validate all supplied NSEC RRsets and signatures against authenticated zone keys.
- [ ] Reject incomplete, contradictory, out-of-zone, malformed, or unauthenticated proof material.
- [ ] Add deterministic signed-zone fixtures for normal, boundary, wrap-around, apex, delegation, wildcard, and malformed cases.

**Exit criteria:** NSEC proof functions distinguish proven, not-proven, unsupported, and invalid evidence; tests cover relevant proof shapes. No network fetching is required yet.

### Phase 3 — NSEC3 validation

- [ ] Research applicable DNSSEC specifications before implementation.
- [ ] Validate NSEC3 owner hashes, next hashes, hash algorithm, salt, iteration limits, flags, and type bitmaps.
- [ ] Implement exact-match and interval/closest-encloser proof logic required for NXDOMAIN and NODATA.
- [ ] Implement Opt-Out semantics only for cases where the specification permits it.
- [ ] Keep unsupported hash algorithms and excessive iteration parameters bounded and explicitly reported.
- [ ] Add published test vectors plus deterministic local fixtures.
- [ ] Do not treat an NSEC3 record as sufficient proof merely because its hash interval appears to cover a name.

**Exit criteria:** NSEC3 proof semantics are validated independently and cannot produce false Secure/Insecure outcomes.

### Phase 4 — End-to-end DNSSEC validation engine

- [ ] Define a single validation orchestrator with strict dependency boundaries.
- [ ] Start from an explicitly configured trust anchor.
- [ ] Validate root DNSKEY RRset.
- [ ] Resolve and validate each delegation's DS RRset and child DNSKEY RRset.
- [ ] Handle authenticated DS absence using the dedicated NSEC/NSEC3 proof paths.
- [ ] Bound delegation depth, lookups, response size, retries, concurrency, and total elapsed time.
- [ ] Distinguish Secure, Insecure, Bogus, and Indeterminate without unsafe fallback behavior.
- [ ] Define deterministic behavior for unsupported algorithms, missing data, timeout, SERVFAIL, malformed data, and inconsistent responses.
- [ ] Keep DNSSEC validation logic independent from CLI and transport.
- [ ] Add integration tests with local authoritative test servers and signed test zones; do not rely on live public DNS for CI.

**Exit criteria:** a caller can provide or retrieve bounded DNS material and receive a defensible typed validation result rooted in a configured trust anchor. No result is Secure without a complete authenticated path and valid answer/proof.

### Phase 5 — DNSSEC CLI integration and JSON contract

- [ ] Introduce a clear validation command or explicit validation mode; do not silently change the meaning of the existing `--dnssec` record-request option.
- [ ] Keep “DNSSEC records requested” separate from “locally validated”.
- [ ] Expose status, reason, validated zone, trust-anchor identity/source, and relevant proof metadata.
- [ ] Report resolver AD bit separately as resolver-reported metadata.
- [ ] Define stable JSON v1 compatibility rules; add fields additively where possible.
- [ ] Provide useful terminal output for Secure, Insecure, Bogus, and Indeterminate.
- [ ] Ensure non-zero exit codes are documented and consistent for operational errors vs validation outcomes.
- [ ] Add CLI tests for all result statuses and structured errors.

**Exit criteria:** no ambiguity between DO-bit request, resolver AD assertion, and dnsvet local validation.

### Phase 6 — Resolver discovery and transport expansion

- [ ] Add platform-isolated resolver discovery for Windows, Linux, and macOS.
- [ ] Test multiple nameservers, search domains, malformed configuration, and unavailable resolver settings.
- [ ] Add DoT with certificate verification and bounded connection handling.
- [ ] Add DoH with strict TLS verification, bounded response sizes, and safe HTTP timeouts.
- [ ] Keep UDP/TCP behavior unchanged unless compatibility tests justify a change.
- [ ] Add local mock-server tests for all transports.
- [ ] Clearly display transport used and resolver endpoint in reports.

**Exit criteria:** transports are selectable, portable, bounded, tested, and do not weaken TLS verification.

### Phase 7 — DNS diagnostics and resolver intelligence

Implement in small independent features:

- [ ] Resolver benchmark: latency distribution, sample count, timeout/error rate, and repeatability.
- [ ] Resolver comparison using identical query sets and controlled test conditions.
- [ ] DNS leak diagnostics with clearly documented limitations; do not claim leak detection from insufficient evidence.
- [ ] DNS rewriting/poisoning indicators based on repeatable controlled comparisons, not one unexplained mismatch.
- [ ] NXDOMAIN consistency checks across selected resolvers.
- [ ] TTL, response-code, EDNS, DNSSEC capability, and transport diagnostics.
- [ ] DNS trace with bounded depth and query limits.
- [ ] Propagation checks across a user-selected resolver list.
- [ ] Infrastructure diagnostics only when evidence is sufficient.

**Exit criteria:** each diagnostic explains its method, evidence, confidence/limitations, and does not overstate conclusions.

### Phase 8 — Reporting, usability, and release readiness

- [ ] Design a stable human-readable report model shared by terminal and JSON output.
- [ ] Add HTML report generation only after the report model is stable.
- [ ] Ensure HTML output is escaped and safe for untrusted DNS record content.
- [ ] Add version/build metadata and reproducible release artifacts.
- [ ] Build and test Windows, Linux, and macOS binaries.
- [ ] Add installation and upgrade instructions.
- [ ] Add realistic examples and documented limitations.
- [ ] Review license notices and dependency security.
- [ ] Create a release checklist and versioning policy.

**Exit criteria:** clean cross-platform builds, reproducible release process, clear docs, safe output handling, green CI.

---

## 4. Priority Queue — What to Do Next

The next agent session must start with this sequence:

1. Read this file, README, CONTRIBUTING, SECURITY, all ADRs, and the relevant implementation/tests.
2. Inspect current git status, current branch, current HEAD, latest commit, and latest CI. Do not overwrite uncommitted work.
3. Fix the Go version mismatch in CONTRIBUTING.md (README/go.mod are the baseline).
4. Audit Phase 1 DNSSEC primitives. Start with a written list of concrete correctness risks and missing tests.
5. Select one small, demonstrable issue. Add a failing regression test first, implement the minimal fix, then run all required checks.
6. Update this roadmap and relevant docs only with verified outcomes.
7. Stop and report results, changed files, test output, commit SHA, and remaining risks.

Do not begin NSEC3 or recursive network chain fetching before the existing NSEC/DS proof primitives have been audited.

---

## 5. Non-Negotiable Agent Rules

These rules override an agent's default workflow.

### 5.1 Branch and Git rules

1. Work on the existing `main` branch by default.
2. **Never create a branch unless the repository owner explicitly instructs you to create one.**
3. **Never switch to another branch unless explicitly instructed.**
4. Do not create feature branches, temporary branches, worktrees, or detached-HEAD workflows without permission.
5. Do not commit or push unless explicitly instructed by the repository owner.
6. Never force-push, reset, rebase, amend, or rewrite existing history unless explicitly instructed.
7. Before edits, inspect `git status --short --branch` and `git log -5 --oneline`.
8. Preserve pre-existing user changes. Never discard, overwrite, or “clean up” unrelated modifications.
9. If the working tree contains unexpected changes, inspect and report them before proceeding.
10. Do not merge PRs or close issues unless explicitly instructed.

### 5.2 Commit message rules

Only when the owner explicitly asks you to commit, follow these exact formats:

- New file: `✨ Create (v0.0.11)`
- Modification/change: `✨ Change (v0.0.11)`
- Bug fix: `🐛 Fix (v0.0.11)`
- Security fix/hardening: `🛡️ Fix (v0.0.11)`
- Documentation-only change: `📝 Docs (v0.0.11)`

Rules:
- Replace the example version with the agreed next version.
- Do not append descriptions, explanations, scopes, or filenames to the commit subject.
- Use the category that matches the actual change.
- Do not invent or increment a version without checking the existing version/tag policy.
- If multiple categories apply, ask the owner or choose the dominant change type; do not create a hybrid subject.

### 5.3 Versioning rules

- Inspect existing tags and project version conventions before proposing a version.
- Do not bump versions for every internal file edit automatically.
- Do not claim a release exists unless a Git tag/release is present.
- Keep CLI version output and release metadata consistent.
- Document breaking JSON/CLI changes explicitly.

### 5.4 Code quality

- Read surrounding code and tests before editing.
- Prefer minimal, focused patches over broad rewrites.
- Keep package boundaries: CLI in `cmd/dnsvet`, DNS transport in `internal/dnsclient`, validation in `internal/dnssec`.
- Keep OS-specific behavior isolated.
- Prefer standard library unless a dependency provides clear, justified value.
- Add dependencies only after checking maintenance, licensing, security, cross-platform support, and whether existing dependencies already solve the problem.
- Avoid speculative abstractions and premature frameworks.
- No dead code, placeholder implementations, fake success paths, or TODO-only features presented as complete.
- Do not silently change public CLI flags, exit codes, JSON field meaning, or schema behavior.
- All external input (DNS names, DNS records, trust-anchor files, resolver responses) must be validated and bounded.
- Security-sensitive code must fail closed.
- Never convert missing or unsupported evidence into a Secure or Insecure result.

### 5.5 Testing rules

For every code change:
- Add or update tests for the changed behavior.
- Add regression tests for bugs before fixing them where practical.
- Use deterministic local fixtures and local test servers.
- Do not make unit tests depend on 1.1.1.1, 8.8.8.8, or any public DNS service.
- Include negative, malformed, boundary, timeout, and cancellation cases where relevant.
- Run `gofmt` on changed Go files.
- Run `go test ./...`.
- Run `go test -race ./...` on supported environments.
- Run `go vet ./...`.
- Run `go build ./...`.
- Run `go mod tidy -diff` and `go mod verify`.
- Check CI for the exact commit/HEAD being evaluated.
- Never say tests passed if they were not executed. Separate local results from CI results.

### 5.6 DNSSEC correctness rules

- DO bit means “request DNSSEC records”; it does not mean “validate DNSSEC”.
- AD bit is a resolver assertion; it is not dnsvet's local cryptographic validation.
- Secure requires a complete valid chain to a configured trust anchor plus valid answer/proof.
- Insecure requires authenticated proof of unsigned delegation.
- Bogus means authenticated material is cryptographically invalid or contradictory.
- Indeterminate means evidence is incomplete, unavailable, or unsupported.
- Do not downgrade Bogus to Insecure.
- Keep NSEC interval membership, NODATA, NXDOMAIN, wildcard denial, and DS-absence-at-delegation as distinct proof semantics.
- NSEC3 Opt-Out must never be treated as generic proof.
- Bound chain depth, NSEC3 iterations, records, message size, network calls, concurrency, and total execution time.
- Document exactly which RFC behavior and test vectors support each validation feature.

### 5.7 Documentation rules

- Update README when user-visible functionality, setup, commands, or limitations change.
- Update CLI examples and help text with CLI changes.
- Update JSON schema documentation when output changes.
- Add/update ADRs when architecture or security decisions materially change.
- Keep roadmap checkboxes honest; mark complete only after implementation and tests.
- Never document planned features as implemented.
- Keep Go version references consistent with go.mod.

### 5.8 Communication and delivery rules

At the end of each task, report:
1. What was inspected.
2. What changed and why.
3. Exact files changed.
4. Tests/checks executed and their actual outcomes.
5. CI status for the current commit, if available.
6. Commit SHA only if a commit was explicitly authorized and created.
7. Remaining risks and the recommended next single task.

Do not claim success based solely on code generation. Do not hide failed tests. Do not make broad changes without explaining their impact.

---

## 6. Definition of Done

A task is done only when:
- The intended behavior is implemented.
- Tests cover success and relevant failure/edge cases.
- Formatting, vet, tests, build, and module checks pass as applicable.
- Existing CLI and JSON compatibility is preserved or intentionally documented.
- Security assumptions and limitations are explicit.
- Relevant documentation is updated.
- The working tree contains no accidental changes.
- No unauthorized branch, commit, push, merge, or release action was performed.

A phase is done only when its exit criteria are met. A feature is not complete merely because it compiles.

---

## 7. Agent Start Prompt

Use the following instruction when assigning the next task:

> Continue dnsvet development using PLAN.md as the authoritative roadmap and agent rulebook. First inspect the current repository state, current branch, git status, recent commits, README, CONTRIBUTING, SECURITY, ADRs, implementation, tests, and latest CI for the exact HEAD. Do not create/switch branches, commit, push, merge, or rewrite history. Start with Phase 0 consistency work and Phase 1 DNSSEC audit as described in the priority queue. Identify concrete correctness gaps, add regression tests before fixes, implement only one focused change at a time, run all required checks, update documentation and roadmap honestly, and report exact outcomes. Do not start NSEC3 or recursive network fetching until the existing proof primitives have been audited. Follow the exact commit subject formats only if the owner later authorizes a commit.

