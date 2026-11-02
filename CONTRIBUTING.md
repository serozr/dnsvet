# Contributing

Thanks for considering a contribution to dnsvet.

## Development requirements

- Go 1.27.3 or later.
- Run `gofmt` on changed Go files.
- Run `go vet ./...`.
- Run `go test ./...`.
- Keep tests deterministic and avoid depending on public DNS services.

## Pull requests

- Explain the problem and the behavior being changed.
- Include tests for new behavior and bug fixes.
- Keep changes focused and small.
- Update documentation when CLI behavior or configuration changes.
- Do not add flooding, denial-of-service, DNS amplification, or unauthorized exploitation features.

## Design expectations

Prefer the Go standard library where practical. Add dependencies only when they provide clear value and are suitable for cross-platform use.
