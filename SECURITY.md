# Security Policy

## Supported versions

dnsvet is in early development. Security fixes are currently applied to the latest code on the `main` branch.

## Reporting a vulnerability

Please do not disclose suspected vulnerabilities in a public issue.

Report security concerns privately through the repository owner's GitHub contact options. Include a clear description, reproduction steps, potential impact, and relevant logs or proof of concept.

Do not include credentials, private keys, or other secrets in a report.

## Safe-use principles

dnsvet is designed for authorized, low-impact DNS diagnostics. It must not implement DNS flooding, denial-of-service, amplification, or exploitation features. Network operations should use bounded timeouts and conservative concurrency.
