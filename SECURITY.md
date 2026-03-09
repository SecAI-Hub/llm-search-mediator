# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in llm-search-mediator, please report it responsibly:

1. **GitHub Security Advisories** (preferred): [Report a vulnerability](https://github.com/SecAI-Hub/llm-search-mediator/security/advisories/new)

**Do not** open a public GitHub issue for security vulnerabilities.

## Response timeline

| Stage | Target |
|---|---|
| Acknowledgement | 48 hours |
| Triage and severity assessment | 7 days |
| Fix for Critical/High | 90 days |

## Scope

### In scope

- PII stripping bypass (patterns that leak through)
- Prompt injection filter bypass (adversarial text that passes)
- Query uniqueness detection bypass
- Audit log tampering or chain integrity bypass
- Denial of service via crafted queries
- Information leakage through timing, padding, or error messages

### Out of scope

- Vulnerabilities in Flask, requests, or PyYAML
- SearXNG or Tor vulnerabilities
- Deployment misconfigurations

## Supported versions

Only the latest release on the `main` branch is supported.
